from app import create_app
from models import db, User
from services.email_service import issue_user_otp, verify_user_otp
from datetime import datetime, timezone, timedelta

def test_password_hashing():
    app = create_app('testing')
    with app.app_context():
        user = User(username='test_sec_user', email='sec_user@example.com')
        user.set_password('SuperSecretPass123!')
        assert user.password_hash != 'SuperSecretPass123!'
        assert user.check_password('SuperSecretPass123!') is True
        assert user.check_password('WrongPass') is False

def test_otp_flow_and_expiration():
    app = create_app('testing')
    with app.app_context():
        user = User(username='otp_user', email='otp_user@example.com')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        
        # 1. Issue OTP
        otp, sent, msg = issue_user_otp(user)
        assert len(otp) == 6
        assert user.otp_code == otp
        assert user.otp_attempts == 0
        
        # 2. Test wrong code increments attempt counter
        success, message = verify_user_otp(user, '000000')
        assert success is False
        assert user.otp_attempts == 1
        
        # 3. Test correct code verifies user
        success, message = verify_user_otp(user, otp)
        assert success is True
        assert user.is_verified is True
        assert user.otp_code is None
        
        # 4. Test expired OTP
        user.otp_code = '123456'
        user.otp_expiry = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.session.commit()
        
        success, message = verify_user_otp(user, '123456')
        assert success is False
        assert "expired" in message.lower()

def test_user_isolation():
    app = create_app('testing')
    with app.app_context():
        u1 = User(username='user1', email='u1@example.com')
        u1.set_password('Pass123456')
        u2 = User(username='user2', email='u2@example.com')
        u2.set_password('Pass123456')
        db.session.add_all([u1, u2])
        db.session.commit()
        
        assert u1.id != u2.id

