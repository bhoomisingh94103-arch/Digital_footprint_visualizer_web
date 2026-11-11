from datetime import datetime, timezone
import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

def utcnow():
    return datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # OTP security fields
    otp_code = db.Column(db.String(8), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0, nullable=False)
    
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    email_assessments = db.relationship('EmailAssessment', backref='user', lazy=True, cascade='all, delete-orphan')
    questionnaire_assessments = db.relationship('QuestionnaireAssessment', backref='user', lazy=True, cascade='all, delete-orphan')
    ip_assessments = db.relationship('IPAssessment', backref='user', lazy=True, cascade='all, delete-orphan')
    recommendation_progress = db.relationship('UserRecommendationProgress', backref='user', lazy=True, cascade='all, delete-orphan')
    action_checklists = db.relationship('ActionChecklistItem', backref='user', lazy=True, cascade='all, delete-orphan')
    pdf_reports = db.relationship('PDFReport', backref='user', lazy=True, cascade='all, delete-orphan')
    chat_logs = db.relationship('ChatHistory', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class EmailAssessment(db.Model):
    __tablename__ = 'email_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    risk_score = db.Column(db.Integer, default=0, nullable=False)  # 0 to 100
    risk_level = db.Column(db.String(32), default='Low', nullable=False)  # Low, Moderate, High, Critical
    breach_count = db.Column(db.Integer, default=0, nullable=False)
    paste_count = db.Column(db.Integer, default=0, nullable=False)
    xposed_records_total = db.Column(db.BigInteger, default=0, nullable=False)
    reputation_status = db.Column(db.String(64), default='Unknown', nullable=False)
    status = db.Column(db.String(32), default='completed', nullable=False)  # completed, partial, failed
    raw_data_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    
    breach_findings = db.relationship('BreachFinding', backref='assessment', lazy=True, cascade='all, delete-orphan')
    email_rep_checks = db.relationship('EmailRepCheck', backref='assessment', lazy=True, cascade='all, delete-orphan')

    def get_raw_data(self):
        if self.raw_data_json:
            try:
                return json.loads(self.raw_data_json)
            except Exception:
                return {}
        return {}


class BreachFinding(db.Model):
    __tablename__ = 'breach_findings'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('email_assessments.id'), nullable=False, index=True)
    breach_name = db.Column(db.String(128), nullable=False)
    domain = db.Column(db.String(128), nullable=True)
    breach_date = db.Column(db.String(64), nullable=True)
    pwn_count = db.Column(db.BigInteger, default=0, nullable=False)
    description = db.Column(db.Text, nullable=True)
    data_classes = db.Column(db.Text, nullable=True)  # Semicolon separated data items
    is_verified = db.Column(db.Boolean, default=True, nullable=False)
    password_risk = db.Column(db.String(64), default='unknown', nullable=True)
    logo_url = db.Column(db.String(255), nullable=True)
    industry = db.Column(db.String(128), nullable=True)

    def get_data_classes_list(self):
        if not self.data_classes:
            return []
        return [item.strip() for item in self.data_classes.split(';') if item.strip()]


class EmailRepCheck(db.Model):
    __tablename__ = 'email_rep_checks'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('email_assessments.id'), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False)
    reputation = db.Column(db.String(64), default='unavailable', nullable=False)  # high, medium, low, none, unavailable
    suspicious = db.Column(db.Boolean, default=False, nullable=False)
    references_count = db.Column(db.Integer, default=0, nullable=False)
    is_disposable = db.Column(db.Boolean, default=False, nullable=False)
    is_free_provider = db.Column(db.Boolean, default=False, nullable=False)
    domain_reputation = db.Column(db.String(64), default='unknown', nullable=True)
    details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class IPAssessment(db.Model):
    __tablename__ = 'ip_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    country = db.Column(db.String(64), nullable=True)
    city = db.Column(db.String(64), nullable=True)
    isp = db.Column(db.String(128), nullable=True)
    org = db.Column(db.String(128), nullable=True)
    asn = db.Column(db.String(64), nullable=True)
    is_vpn = db.Column(db.Boolean, default=False, nullable=False)
    is_proxy = db.Column(db.Boolean, default=False, nullable=False)
    is_tor = db.Column(db.Boolean, default=False, nullable=False)
    network_type = db.Column(db.String(64), default='residential/other', nullable=True)
    threat_score = db.Column(db.Integer, default=0, nullable=False)
    status = db.Column(db.String(32), default='completed', nullable=False)
    raw_response_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class QuestionnaireAssessment(db.Model):
    __tablename__ = 'questionnaire_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    overall_score = db.Column(db.Integer, nullable=False)  # 0 to 100
    risk_level = db.Column(db.String(32), nullable=False)  # Low, Moderate, High, Critical
    category_scores_json = db.Column(db.Text, nullable=False)  # JSON {Auth: 40, Network: 60, ...}
    responses_json = db.Column(db.Text, nullable=False)  # JSON question_id -> answer
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    def get_category_scores(self):
        try:
            return json.loads(self.category_scores_json)
        except Exception:
            return {}

    def get_responses(self):
        try:
            return json.loads(self.responses_json)
        except Exception:
            return {}


class Recommendation(db.Model):
    __tablename__ = 'recommendations'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(64), nullable=False)  # Authentication, Network, Identity, Social Media, Browsing, Device Security
    priority = db.Column(db.String(32), nullable=False)  # Critical, High, Medium, Low
    reason = db.Column(db.Text, nullable=False)
    action_steps = db.Column(db.Text, nullable=False)
    external_url = db.Column(db.String(255), nullable=True)

    def get_steps_list(self):
        return [s.strip() for s in self.action_steps.split('\n') if s.strip()]


class UserRecommendationProgress(db.Model):
    __tablename__ = 'user_recommendation_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    recommendation_id = db.Column(db.Integer, db.ForeignKey('recommendations.id'), nullable=False)
    assessment_id = db.Column(db.Integer, nullable=True)
    assessment_type = db.Column(db.String(32), default='email')  # email or questionnaire
    is_completed = db.Column(db.Boolean, default=False, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)

    recommendation = db.relationship('Recommendation', backref='user_progress', lazy=True)


class ActionChecklistItem(db.Model):
    __tablename__ = 'action_checklist_items'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    guide_id = db.Column(db.String(64), nullable=False, index=True)  # password, 2fa, social, etc.
    task_id = db.Column(db.String(64), nullable=False)
    is_completed = db.Column(db.Boolean, default=False, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class PDFReport(db.Model):
    __tablename__ = 'pdf_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    assessment_id = db.Column(db.Integer, nullable=False)
    assessment_type = db.Column(db.String(32), nullable=False)  # email, questionnaire
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    risk_level = db.Column(db.String(32), default='Low', nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class ChatHistory(db.Model):
    __tablename__ = 'chat_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    session_id = db.Column(db.String(64), nullable=False, index=True)
    role = db.Column(db.String(16), nullable=False)  # user, assistant
    content = db.Column(db.Text, nullable=False)
    model_used = db.Column(db.String(64), default='Privacy Guardian Expert Engine', nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow, nullable=False)


class ApiActivityLog(db.Model):
    __tablename__ = 'api_activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    api_name = db.Column(db.String(64), nullable=False, index=True)
    endpoint = db.Column(db.String(255), nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    response_time_ms = db.Column(db.Integer, nullable=True)
    success = db.Column(db.Boolean, default=True, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

