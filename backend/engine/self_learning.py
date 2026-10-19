import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)
RETRAIN_THRESHOLD = 10

class SelfLearningEngine:
    def __init__(self, analyzer, db_client):
        self.analyzer = analyzer
        self.db = db_client
        self.scheduler = BackgroundScheduler(daemon=True)
        self._retrain_count = 0
        self._is_running = False
        self._last_count = self._load_last_count()

    def _load_last_count(self) -> int:
        try:
            version = self.db.get_latest_model_version()
            if version and version.get('training_samples'):
                return int(version['training_samples'])
        except Exception as e:
            logger.warning(f"Could not restore retrain count: {e}")
        return 0

    def start(self):
        if self._is_running:
            return
        self.scheduler.add_job(
            func=self._check_and_retrain,
            trigger=IntervalTrigger(minutes=30),
            id='sentinel_retrain',
            name='SENTINEL Self-Learning Retrain Job',
            replace_existing=True,
            next_run_time=datetime.now(),
        )
        self.scheduler.start()
        self._is_running = True

    def stop(self):
        if self._is_running:
            self.scheduler.shutdown(wait=False)
            self._is_running = False

    def status(self) -> dict:
        return {
            'is_running': self._is_running,
            'retrain_threshold': RETRAIN_THRESHOLD,
            'total_retrains': self._retrain_count,
            'last_known_count': self._last_count,
        }

    def _check_and_retrain(self):
        try:
            reports = self.db.fetch_confirmed_scams()
            if not reports:
                return

            current_count = len(reports)
            new_since_last = current_count - self._last_count
            if new_since_last < RETRAIN_THRESHOLD:
                return

            samples = [r['message_text'] for r in reports if r.get('message_text')]
            result = self.analyzer.retrain(samples)
            self._last_count = current_count

            if not result:
                return

            self._retrain_count += 1
            notes = (
                f"Auto-retrain #{self._retrain_count}. "
                f"Added {result['added_samples']} new samples. "
                f"Discovered {len(result.get('new_terms', []))} new trigger terms"
            )

            self.db.log_model_version(
                version=result['new_version'],
                corpus_size=result['new_corpus_size'],
                keyword_count=result['keyword_count'],
                training_samples=current_count,
                notes=notes,
            )
        except Exception as e:
            logger.error(f"Self-learning retrain failed: {e}", exc_info=True)

    def force_retrain(self) -> dict:
        reports = self.db.fetch_confirmed_scams()
        if not reports:
            return {'success': False, 'message': 'No confirmed scam reports available.'}

        samples = [r['message_text'] for r in reports if r.get('message_text')]
        result = self.analyzer.retrain(samples)
        if not result:
            return {
                'success': False,
                'message': 'Retrain skipped or validation failed and was rolled back.',
            }

        current_count = len(reports)
        self._last_count = current_count
        self._retrain_count += 1
        self.db.log_model_version(
            version=result['new_version'],
            corpus_size=result['new_corpus_size'],
            keyword_count=result['keyword_count'],
            training_samples=current_count,
            notes=f"Manual retrain #{self._retrain_count} via API.",
        )

        return {
            'success': True,
            'version': result['new_version'],
            'corpus_size': result['new_corpus_size'],
            'added_samples': result['added_samples'],
            'new_terms': result.get('new_terms', []),
            'keyword_count': result['keyword_count'],
        }
