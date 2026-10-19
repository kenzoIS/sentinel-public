# =============================================================
# SENTINEL — Self-Learning Engine
# Monitors Supabase for new confirmed scams and auto-retrains
# =============================================================

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
        logger.info(f"Self-learning engine initialized. Last known report count: {self._last_count}")

    def _load_last_count(self) -> int:
        try:
            version = self.db.get_latest_model_version()
            if version and version.get('training_samples'):
                count = int(version['training_samples'])
                logger.info(f"Self-learning: restored last_count={count} from model_versions table.")
                return count
        except Exception as e:
            logger.warning(f"Self-learning: could not load last_count from Supabase: {e}. Defaulting to 0.")
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
        logger.info(f"Self-learning engine STARTED. Checking every 30 min. Threshold: {RETRAIN_THRESHOLD} new reports.")

    def stop(self):
        if self._is_running:
            self.scheduler.shutdown(wait=False)
            self._is_running = False
            logger.info("Self-learning engine STOPPED.")

    def status(self) -> dict:
        return {
            'is_running': self._is_running,
            'retrain_threshold': RETRAIN_THRESHOLD,
            'total_retrains': self._retrain_count,
            'last_known_count': self._last_count,
        }

    def _check_and_retrain(self):
        try:
            logger.info("Self-learning: Checking for new confirmed scam reports...")
            reports = self.db.fetch_confirmed_scams()
            if not reports:
                logger.info("Self-learning: No confirmed scam reports in database yet.")
                return
            current_count = len(reports)
            new_since_last = current_count - self._last_count
            logger.info(f"Self-learning: {current_count} total reports | {new_since_last} new since last check | Need {RETRAIN_THRESHOLD} to retrain")
            if new_since_last < RETRAIN_THRESHOLD:
                logger.info(f"Self-learning: Waiting for more reports. Progress: {new_since_last}/{RETRAIN_THRESHOLD}")
                return
            logger.info(f"Self-learning: Threshold reached ({new_since_last} new reports). Initiating retraining...")
            samples = [r['message_text'] for r in reports if r.get('message_text')]
            result = self.analyzer.retrain(samples)
            if not result:
                logger.info("Self-learning: Retrain returned no result — either no new unique samples or the new model failed validation and was rolled back.")
                self._last_count = current_count
                return
            self._last_count = current_count
            self._retrain_count += 1
            notes = f"Auto-retrain #{self._retrain_count}. Added {result['added_samples']} new samples. Discovered {len(result.get('new_terms', []))} new trigger terms"
            if result.get('new_terms'):
                notes += f": {result['new_terms'][:5]}"
            self.db.log_model_version(
                version=result['new_version'],
                corpus_size=result['new_corpus_size'],
                keyword_count=result['keyword_count'],
                training_samples=current_count,
                notes=notes,
            )
            logger.info(f"Self-learning: Retrain #{self._retrain_count} COMPLETE. Model v{result['new_version']}. Corpus: {result['new_corpus_size']} samples. Keywords: {result['keyword_count']}.")
        except Exception as e:
            logger.error(f"Self-learning ERROR in _check_and_retrain: {e}", exc_info=True)

    def force_retrain(self) -> dict:
        logger.info("Self-learning: MANUAL retrain triggered via API.")
        reports = self.db.fetch_confirmed_scams()
        if not reports:
            return {'success': False, 'message': 'No confirmed scam reports in database. Submit some feedback first.'}
        samples = [r['message_text'] for r in reports if r.get('message_text')]
        result = self.analyzer.retrain(samples)
        if not result:
            return {'success': False, 'message': 'Retrain skipped — either no new unique samples to add, or the new model failed validation and was rolled back.'}
        current_count = len(reports)
        self._last_count = current_count
        self._retrain_count += 1
        self.db.log_model_version(
            version=result['new_version'],
            corpus_size=result['new_corpus_size'],
            keyword_count=result['keyword_count'],
            training_samples=current_count,
            notes=f"Manual retrain #{self._retrain_count} via /api/retrain endpoint.",
        )
        return {
            'success': True,
            'version': result['new_version'],
            'corpus_size': result['new_corpus_size'],
            'added_samples': result['added_samples'],
            'new_terms': result.get('new_terms', []),
            'keyword_count': result['keyword_count'],
        }
