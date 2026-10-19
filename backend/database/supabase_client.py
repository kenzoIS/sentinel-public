# =============================================================
# SENTINEL — Supabase Database Client
# =============================================================

import os
import logging
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class SupabaseClient:
    def __init__(self):
        url = os.getenv('SUPABASE_URL', '').strip()
        key = os.getenv('SUPABASE_KEY', '').strip()
        if not url or not key:
            raise ValueError(
                "SUPABASE_URL and SUPABASE_KEY must be set in your .env file. "
                "Get them from your Supabase project → Settings → API."
            )
        self.client: Client = create_client(url, key)
        logger.info("Supabase client initialized.")

    def log_analysis(self, message_text: str, result: dict) -> dict | None:
        try:
            payload = {
                'message_text': message_text[:2000],
                'risk_level': result['risk_level'],
                'composite_score': result['composite_score'],
                'similarity_score': result['layers']['layer1']['score'],
                'urgency_score': result['layers']['layer2']['score'],
                'red_flag_score': result['layers']['layer3']['score'],
                'triggered_keywords': [t['keyword'] for t in result['layers']['layer2']['triggered_keywords']],
                'triggered_patterns': result['layers']['layer3']['flagged_phrases'],
                'recommendation': result['recommendation'][:1000],
                'model_version': result['model_version'],
            }
            response = self.client.table('analysis_logs').insert(payload).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"log_analysis failed: {e}")
            return None

    def submit_feedback(self, log_id: str, feedback: str, message_text: str = None) -> bool:
        try:
            self.client.table('analysis_logs').update({'user_feedback': feedback}).eq('id', log_id).execute()
            logger.info(f"Feedback '{feedback}' written to analysis_logs. Log ID: {log_id}")
        except Exception as e:
            logger.error(f"submit_feedback STEP 1 FAILED (analysis_logs update): {e}")
            return False
        if feedback == 'confirmed_scam':
            if not message_text or not message_text.strip():
                logger.warning(f"submit_feedback: feedback is 'confirmed_scam' but message_text is empty. Scam report NOT added. Log ID: {log_id}")
                return True
            try:
                insert_resp = self.client.table('scam_reports').insert({
                    'message_text': message_text.strip()[:2000],
                    'report_source': 'user_feedback',
                    'is_verified': True,
                    'analysis_log_id': log_id,
                }).execute()
                if insert_resp.data:
                    logger.info(f"Scam report inserted into scam_reports. Log ID: {log_id}")
                else:
                    logger.warning("scam_reports insert returned no data. Review your Supabase RLS policies and grants for this project.")
            except Exception as e:
                logger.error(f"submit_feedback STEP 2 FAILED (scam_reports insert): {e}. Review least-privilege Supabase RLS policies and grants.")
                return True
        return True

    def fetch_confirmed_scams(self) -> list:
        try:
            response = self.client.table('scam_reports').select('message_text, category, report_source').eq('is_verified', True).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"fetch_confirmed_scams failed: {e}")
            return []

    def submit_manual_report(self, message_text: str, category: str = 'unknown') -> dict | None:
        try:
            response = self.client.table('scam_reports').insert({
                'message_text': message_text.strip()[:2000],
                'report_source': 'manual',
                'is_verified': True,
                'category': category,
            }).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"submit_manual_report failed: {e}")
            return None

    def log_model_version(self, version: int, corpus_size: int, keyword_count: int, training_samples: int, notes: str = None) -> None:
        try:
            self.client.table('model_versions').upsert({
                'version_number': version,
                'corpus_size': corpus_size,
                'keyword_count': keyword_count,
                'training_samples': training_samples,
                'notes': notes,
            }, on_conflict='version_number').execute()
        except Exception as e:
            logger.error(f"log_model_version failed: {e}")

    def get_latest_model_version(self) -> dict | None:
        try:
            response = self.client.table('model_versions').select('*').order('version_number', desc=True).limit(1).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"get_latest_model_version failed: {e}")
            return None

    def get_model_history(self) -> list:
        try:
            response = self.client.table('model_versions').select('*').order('version_number', desc=True).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"get_model_history failed: {e}")
            return []

    def get_stats(self) -> dict:
        try:
            logs_resp = self.client.table('analysis_logs').select('risk_level, created_at').execute()
            reports_resp = self.client.table('scam_reports').select('id, created_at').eq('is_verified', True).execute()
            version_resp = self.get_latest_model_version()
            logs = logs_resp.data or []
            reports = reports_resp.data or []
            risk_dist = {}
            for log in logs:
                level = log['risk_level']
                risk_dist[level] = risk_dist.get(level, 0) + 1
            scam_count = risk_dist.get('CRITICAL', 0) + risk_dist.get('DANGER', 0)
            return {
                'total_analyses': len(logs),
                'scam_reports': len(reports),
                'scams_detected': scam_count,
                'safe_messages': risk_dist.get('SAFE', 0),
                'risk_distribution': risk_dist,
                'detection_rate': round(scam_count / max(len(logs), 1) * 100, 1),
                'latest_model': version_resp,
            }
        except Exception as e:
            logger.error(f"get_stats failed: {e}")
            return {'total_analyses':0,'scam_reports':0,'scams_detected':0,'safe_messages':0,'risk_distribution':{},'detection_rate':0,'latest_model':None}

    def get_recent_logs(self, limit: int = 10) -> list:
        try:
            response = self.client.table('analysis_logs').select('id, risk_level, composite_score, created_at, user_feedback').order('created_at', desc=True).limit(limit).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"get_recent_logs failed: {e}")
            return []
