import os
from flask import Flask, render_template, request, session
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from config import config_by_name
from models import db, User, EmailAssessment, QuestionnaireAssessment
from services.recommendation_engine import seed_recommendations

csrf = CSRFProtect()
login_manager = LoginManager()

def create_app(config_name=None):
    """Application factory for Digital Footprint Intelligence."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
        
    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name['default']))
    
    # Initialize Extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access your cybersecurity intelligence vault.'
    login_manager.login_message_category = 'info'
    
    # Exempt API JSON endpoints from CSRF for seamless single-page application experience
    csrf.exempt('routes.assessment_routes.api_scan_email')
    csrf.exempt('routes.assessment_routes.api_submit_quiz')
    csrf.exempt('routes.action_center_routes.toggle_task')
    csrf.exempt('routes.action_center_routes.toggle_recommendation')
    csrf.exempt('routes.api_status_routes.ping_service')
    csrf.exempt('routes.chat_routes.send_chat')
    csrf.exempt('routes.chat_routes.clear_chat_history')

    # Register Blueprints
    from routes.auth_routes import auth_bp
    from routes.assessment_routes import assessment_bp
    from routes.dashboard_routes import dashboard_bp
    from routes.action_center_routes import action_center_bp
    from routes.api_status_routes import api_status_bp
    from routes.chat_routes import chat_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(assessment_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(action_center_bp)
    app.register_blueprint(api_status_bp)
    app.register_blueprint(chat_bp)

    # User loader
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Landing page
    @app.route('/')
    def index():
        total_scanned = EmailAssessment.query.count() + QuestionnaireAssessment.query.count()
        return render_template('index.html', total_scanned=total_scanned)

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
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
