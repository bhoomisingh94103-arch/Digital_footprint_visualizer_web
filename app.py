import os
from flask import Flask, render_template, request, session, jsonify
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config_by_name
from models import db, User, EmailAssessment, QuestionnaireAssessment
from services.recommendation_engine import seed_recommendations

csrf = CSRFProtect()
login_manager = LoginManager()


def create_app(config_name=None):
    """Application factory for Digital Footprint Intelligence."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'production')

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name['default']))

    # Configure ProxyFix for reverse proxy support (Render / Cloud / Nginx)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize Extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access your cybersecurity intelligence vault.'
    login_manager.login_message_category = 'info'

    # Register Blueprints
    from routes.auth_routes import auth_bp
    from routes.assessment_routes import (
        assessment_bp,
        api_request_scan_otp,
        api_verify_scan_otp,
        api_scan_email,
        api_submit_quiz
    )
    from routes.dashboard_routes import dashboard_bp
    from routes.action_center_routes import (
        action_center_bp,
        toggle_task,
        toggle_recommendation
    )
    from routes.api_status_routes import api_status_bp, ping_service
    from routes.chat_routes import chat_bp, send_chat, clear_chat_history

    app.register_blueprint(auth_bp)
    app.register_blueprint(assessment_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(action_center_bp)
    app.register_blueprint(api_status_bp)
    app.register_blueprint(chat_bp)

    # Exempt all API JSON endpoints from CSRF using both direct function reference and dotted strings
    api_endpoints = [
        api_request_scan_otp,
        api_verify_scan_otp,
        api_scan_email,
        api_submit_quiz,
        toggle_task,
        toggle_recommendation,
        ping_service,
        send_chat,
        clear_chat_history
    ]
    for ep in api_endpoints:
        try:
            csrf.exempt(ep)
        except Exception:
            pass

    named_exemptions = [
        'routes.assessment_routes.api_request_scan_otp',
        'routes.assessment_routes.api_verify_scan_otp',
        'routes.assessment_routes.api_scan_email',
        'routes.assessment_routes.api_submit_quiz',
        'routes.action_center_routes.toggle_task',
        'routes.action_center_routes.toggle_recommendation',
        'routes.api_status_routes.ping_service',
        'routes.chat_routes.send_chat',
        'routes.chat_routes.clear_chat_history'
    ]
    for name in named_exemptions:
        try:
            csrf.exempt(name)
        except Exception:
            pass

    # User loader
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Landing page
    @app.route('/')
    def index():
        total_scanned = EmailAssessment.query.count() + QuestionnaireAssessment.query.count()
        return render_template('index.html', total_scanned=total_scanned)

    # Helper to detect API requests
    def is_api_request():
        return (
            request.path.startswith('/api/') or
            '/api/' in request.path or
            request.is_json or
            'application/json' in request.headers.get('Accept', '') or
            'application/json' in request.headers.get('Content-Type', '')
        )

    # JSON-aware Error Handlers
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        if is_api_request():
            return jsonify({
                'success': False,
                'error': f"CSRF validation failed: {getattr(e, 'description', 'Invalid or missing security token.')}"
            }), 400
        return render_template('errors/400.html', description=getattr(e, 'description', 'CSRF validation failed.')), 400

    @app.errorhandler(400)
    def bad_request(e):
        if is_api_request():
            return jsonify({
                'success': False,
                'error': getattr(e, 'description', 'Bad Request: Invalid payload or parameters.')
            }), 400
        return render_template('errors/400.html', description=getattr(e, 'description', 'Bad Request')), 400

    @app.errorhandler(404)
    def page_not_found(e):
        if is_api_request():
            return jsonify({
                'success': False,
                'error': 'The requested cybersecurity endpoint does not exist.'
            }), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        if is_api_request():
            return jsonify({
                'success': False,
                'error': f"HTTP method '{request.method}' not allowed on this endpoint."
            }), 405
        return render_template('errors/404.html'), 405

    @app.errorhandler(500)
    def internal_server_error(e):
        if is_api_request():
            return jsonify({
                'success': False,
                'error': 'Internal server error while executing threat processing routines.'
            }), 500
        return render_template('errors/500.html'), 500

    # Context processors
    @app.context_processor
    def inject_global_vars():
        return {
            'app_name': 'Digital Footprint Intelligence',
            'tagline': 'Discover Your Digital Presence. Understand Your Risks. Take Control.',
            'current_year': 2026,
            'is_authenticated': current_user.is_authenticated if current_user else False,
            'current_user': current_user
        }

    # Initialize database tables and recommendation catalog
    with app.app_context():
        db.create_all()
        seed_recommendations()

    return app


if __name__ == '__main__':
    app = create_app('development')
    print("==================================================================")
    print(" DIGITAL FOOTPRINT INTELLIGENCE - PLATFORM READY")
    print(" URL: http://127.0.0.1:5000")
    print("==================================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
