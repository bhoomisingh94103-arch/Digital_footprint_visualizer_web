from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, EmailAssessment, QuestionnaireAssessment
from services.email_service import issue_user_otp, verify_user_otp
from services.email_verifier import validate_email_syntax, check_domain_mx
from datetime import datetime, timezone

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # 1. Username validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long.', 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        # 2. Email syntax validation
        is_valid_syntax, clean_email, syntax_err = validate_email_syntax(email)
        if not is_valid_syntax:
            flash(syntax_err, 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        # 3. Domain MX check
        has_mx, mx_hosts, mx_err = check_domain_mx(clean_email)
        if not has_mx:
            flash(mx_err, 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        # 4. Password validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        # 5. Check existing user
        if User.query.filter_by(username=username).first():
            flash('This username is already taken. Please choose another.', 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        if User.query.filter_by(email=clean_email).first():
            flash('An account with this email address already exists. Please log in.', 'danger')
            return redirect(url_for('auth.login'))

        # 6. Create user record
        new_user = User(
            username=username,
            email=clean_email,
            is_verified=False
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # 7. Issue OTP via SMTP
        otp, sent, msg = issue_user_otp(new_user)

        if not sent:
            # If OTP delivery fails, abort registration & rollback user to prevent unverified phantom records
            db.session.delete(new_user)
            db.session.commit()
            flash(msg, 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        session['verify_user_id'] = new_user.id
        flash(f"Verification OTP has been sent via SMTP to {clean_email}. Please enter the 6-digit code.", 'success')
        return redirect(url_for('auth.verify_otp'))

    return render_template('auth/signup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        # User can log in with username or email
        user = User.query.filter((User.email == login_id) | (User.username == login_id)).first()

        if not user or not user.check_password(password):
            flash('Invalid email/username or password.', 'danger')
            return render_template('auth/login.html', login_id=login_id)

        # If user is not verified, require OTP verification
        if not user.is_verified:
            otp, sent, msg = issue_user_otp(user)
            if not sent:
                flash(msg, 'danger')
                return render_template('auth/login.html', login_id=login_id)

            session['verify_user_id'] = user.id
            flash("Your account email is not yet verified. A new OTP has been sent to your email.", 'info')
            return redirect(url_for('auth.verify_otp'))

        # Log user in
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        login_user(user, remember=remember)

        flash(f"Welcome back, {user.username}!", 'success')
        next_page = request.args.get('next')
        return redirect(next_page if next_page else url_for('dashboard.index'))

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('index'))


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    user_id = session.get('verify_user_id')
    if not user_id:
        flash('No pending verification session found. Please sign up or log in.', 'info')
        return redirect(url_for('auth.login'))

    user = db.session.get(User, user_id)
    if not user:
        session.pop('verify_user_id', None)
        return redirect(url_for('auth.signup'))

    if request.method == 'POST':
        code = request.form.get('otp_code', '').strip()
        success, message = verify_user_otp(user, code)

        if success:
            session.pop('verify_user_id', None)
            login_user(user)
            flash('Email successfully verified! Welcome to Digital Footprint Intelligence.', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash(message, 'danger')
            return render_template('auth/verify_otp.html', email=user.email)

    return render_template('auth/verify_otp.html', email=user.email)


@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    user_id = session.get('verify_user_id')
    if not user_id:
        flash('Verification session expired. Please sign in.', 'warning')
        return redirect(url_for('auth.login'))

    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for('auth.login'))

    otp, sent, msg = issue_user_otp(user)
    if sent:
        flash(f"A fresh verification code was dispatched to {user.email}.", 'success')
    else:
        flash(msg, 'danger')

    return redirect(url_for('auth.verify_otp'))


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        # Validate syntax
        is_valid_syntax, clean_email, syntax_err = validate_email_syntax(email)
        if not is_valid_syntax:
            flash(syntax_err, 'danger')
            return render_template('auth/forgot_password.html')

        user = User.query.filter_by(email=clean_email).first()

        if user:
            otp, sent, msg = issue_user_otp(user)
            if sent:
                session['reset_user_id'] = user.id
                flash(f"Password reset instructions and OTP sent to {clean_email}.", 'success')
                return redirect(url_for('auth.reset_password'))
            else:
                flash(msg, 'danger')
                return render_template('auth/forgot_password.html')
        else:
            # Prevent email enumeration
            flash("If that email address is associated with an account, a reset code has been dispatched.", 'info')
            return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    user_id = session.get('reset_user_id')
    if not user_id:
        flash('No active reset request. Please request a new password reset.', 'warning')
        return redirect(url_for('auth.forgot_password'))

    user = db.session.get(User, user_id)
    if not user:
        session.pop('reset_user_id', None)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('otp_code', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('auth/reset_password.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/reset_password.html')

        success, message = verify_user_otp(user, code)
        if success:
            user.set_password(new_password)
            db.session.commit()
            session.pop('reset_user_id', None)
            flash('Your password has been successfully reset. Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
            return render_template('auth/reset_password.html')

    return render_template('auth/reset_password.html')


@auth_bp.route('/profile')
@login_required
def profile():
    user_scans = EmailAssessment.query.filter_by(user_id=current_user.id).count()
    user_quizzes = QuestionnaireAssessment.query.filter_by(user_id=current_user.id).count()
    return render_template(
        'auth/profile.html',
        user=current_user,
        total_scans=user_scans,
        total_quizzes=user_quizzes
    )
