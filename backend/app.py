# =============================================================
# SENTINEL — Flask API Server
# Philippine Scam Detection AI
# =============================================================

import logging
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

from engine.analyzer import PhishingAnalyzer
from engine.self_learning import SelfLearningEngine
from database.supabase_client import SupabaseClient

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('SENTINEL')

app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path='',
)
CORS(app)

logger.info("Initializing SENTINEL analysis engine...")
analyzer = PhishingAnalyzer()
DB_ACTIVE = False
db = None
learner = None

try:
    db = SupabaseClient()
    learner = SelfLearningEngine(analyzer, db)
    learner.start()
    DB_ACTIVE = True
    logger.info("Supabase connected. Self-learning engine is ACTIVE.")
except Exception as e:
    logger.warning(f"Supabase unavailable ({e}). Running in OFFLINE mode — analysis still works.")

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'online',
        'model_version': analyzer.model_version,
        'corpus_size': len(analyzer.scam_corpus),
        'keyword_count': len(analyzer.keyword_weights),
        'db_connected': DB_ACTIVE,
        'learning_active': learner.status() if learner else None,
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json(silent=True)
    if not data or not data.get('message', '').strip():
        return jsonify({'error': 'A non-empty "message" field is required.'}), 400

    message = data['message'].strip()
    if len(message) < 8:
        return jsonify({'error': 'Message is too short to analyze.'}), 400
    if len(message) > 5000:
        return jsonify({'error': 'Message exceeds 5000 character limit.'}), 400

    result = analyzer.analyze(message)
    log_id = None
    if DB_ACTIVE and db:
        log_entry = db.log_analysis(message, result)
        log_id = log_entry.get('id') if log_entry else None

    result['log_id'] = log_id
    return jsonify(result)

@app.route('/api/feedback', methods=['POST'])
def feedback():
    if not DB_ACTIVE:
        return jsonify({'error': 'Database unavailable in offline mode.'}), 503

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body is required.'}), 400

    log_id = data.get('log_id')
    feedback_value = data.get('feedback')
    message = data.get('message_text', '')

    if not log_id or not feedback_value:
        return jsonify({'error': '"log_id" and "feedback" are required.'}), 400
    if feedback_value not in ['confirmed_scam', 'confirmed_safe']:
        return jsonify({'error': '"feedback" must be "confirmed_scam" or "confirmed_safe".'}), 400

    success = db.submit_feedback(log_id, feedback_value, message)

    if success and feedback_value == 'confirmed_scam':
        reports = db.fetch_confirmed_scams()
        count = len(reports)
        from engine.self_learning import RETRAIN_THRESHOLD
        return jsonify({
            'success': True,
            'message': 'Thank you. This report will help SENTINEL learn.',
            'total_reports': count,
            'next_retrain_in': max(0, RETRAIN_THRESHOLD - (count % RETRAIN_THRESHOLD)),
        })

    return jsonify({'success': success})

@app.route('/api/report', methods=['POST'])
def manual_report():
    if not DB_ACTIVE:
        return jsonify({'error': 'Database unavailable in offline mode.'}), 503

    data = request.get_json(silent=True)
    message = (data or {}).get('message', '').strip()
    category = (data or {}).get('category', 'unknown')

    if not message or len(message) < 10:
        return jsonify({'error': 'A non-empty scam message is required.'}), 400

    entry = db.submit_manual_report(message, category)
    return jsonify({'success': bool(entry), 'entry': entry})

@app.route('/api/retrain', methods=['POST'])
def retrain():
    if not DB_ACTIVE:
        return jsonify({'error': 'Database unavailable in offline mode.'}), 503
    if not learner:
        return jsonify({'error': 'Self-learning engine not initialized.'}), 503

    result = learner.force_retrain()
    return jsonify(result)

@app.route('/api/stats', methods=['GET'])
def stats():
    if not DB_ACTIVE:
        return jsonify({
            'offline': True,
            'model_version': analyzer.model_version,
            'corpus_size': len(analyzer.scam_corpus),
            'keyword_count': len(analyzer.keyword_weights),
        })

    data = db.get_stats()
    data['model_version'] = analyzer.model_version
    data['corpus_size'] = len(analyzer.scam_corpus)
    data['keyword_count'] = len(analyzer.keyword_weights)
    data['db_connected'] = DB_ACTIVE
    data['recent_logs'] = db.get_recent_logs(limit=5)
    data['model_history'] = db.get_model_history()
    data['learning_status'] = learner.status() if learner else None
    return jsonify(data)

@app.route('/api/model-history', methods=['GET'])
def model_history():
    if not DB_ACTIVE:
        return jsonify({'error': 'Database unavailable.'}), 503
    return jsonify(db.get_model_history())

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found.'}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error.'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    logger.info(f"SENTINEL starting on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
