# app.py
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import os
from functools import wraps

# Import database models and session from db.py
from db import db_session, init_db, User, LoginAttempt, BlacklistedIP, Notification

app = Flask(__name__)
# Set a secret key for session management. IMPORTANT: Use a strong, random key in production.
app.config['SECRET_KEY'] = 'ueigqf7p91etef91p_default_secret'

# Initialize the database when the app starts
with app.app_context():
    init_db()
    # Removed the default user creation here, as populate_db.py handles it.
    # You can keep this block if you want a fallback for first run without populate_db.py
    # but it's generally better to separate data seeding from app startup.
    # For now, we assume populate_db.py has already run.
    print("Database tables ensured. Assuming initial users are populated by populate_db.py.")


# --- Authentication and Authorization Decorators ---

def login_required(f):
    """Decorator to ensure a user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to ensure the logged-in user is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index')) # Or redirect to a regular dashboard
        return f(*args, **kwargs)
    return decorated_function


# --- Routes ---

@app.route('/')
def index():
    """Renders the main login page."""
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Handles user login attempts, brute-force detection, and blacklisting."""
    data = request.get_json()
    gmail = data.get('gmail')
    password = data.get('password')
    ip_address = request.remote_addr # Get the client's IP address

    if not gmail or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    # --- Authenticate User First ---
    user = db_session.query(User).filter_by(email=gmail).first()

    # Bypass brute-force checks if the user is an admin and credentials are correct
    if user and user.is_admin and (user.password_hash == password): # Assuming plain text for now
    # if user and user.is_admin and check_password_hash(user.password_hash, password): # Use this if using hashed passwords
        # Successful login for admin
        new_attempt = LoginAttempt(
            email=gmail,
            ip_address=ip_address,
            is_successful=True,
            user_id=user.user_id,
            reason='Successful Admin Login (Bypassed Brute Force Check)'
        )
        db_session.add(new_attempt)
        db_session.commit()

        session['user_id'] = user.user_id
        session['email'] = user.email
        session['is_admin'] = user.is_admin
        return jsonify({'message': 'Login successful!', 'redirect': url_for('admin_dashboard')})


    # --- Brute-Force Detection Logic (only for non-admin attempts or failed admin attempts) ---
    TIME_WINDOW_SECONDS = 30
    FAILED_ATTEMPT_THRESHOLD = 5

    time_threshold = datetime.now() - timedelta(seconds=TIME_WINDOW_SECONDS)

    recent_failed_attempts = db_session.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.attempt_time >= time_threshold,
        LoginAttempt.is_successful == False
    ).count()

    is_blacklisted = db_session.query(BlacklistedIP).filter_by(
        ip_address=ip_address, is_active=True
    ).first()


    if is_blacklisted:
        new_attempt = LoginAttempt(
            email=gmail,
            ip_address=ip_address,
            is_successful=False,
            reason='Blocked: IP blacklisted'
        )
        db_session.add(new_attempt)
        db_session.commit()
        print(f"Blocked login attempt from blacklisted IP: {ip_address}")
        return jsonify({'message': 'Your IP address has been temporarily blocked due to suspicious activity.'}), 403

    if recent_failed_attempts >= FAILED_ATTEMPT_THRESHOLD:
        if not is_blacklisted:
            new_blacklist_entry = BlacklistedIP(
                ip_address=ip_address,
                reason=f'Exceeded {FAILED_ATTEMPT_THRESHOLD} failed login attempts within {TIME_WINDOW_SECONDS} seconds.'
            )
            db_session.add(new_blacklist_entry)
            db_session.commit()

            admin_notification = Notification(
                admin_email='admin@yourdomain.com', # Assuming this is the admin email
                notification_type='Brute Force Alert',
                message=f'IP {ip_address} attempted {recent_failed_attempts + 1} failed logins within {TIME_WINDOW_SECONDS} seconds. IP blacklisted.',
                related_ip=ip_address
            )
            db_session.add(admin_notification)
            db_session.commit()
            print(f"ADMIN ALERT: IP {ip_address} blacklisted due to brute force.")
        
        new_attempt = LoginAttempt(
            email=gmail,
            ip_address=ip_address,
            is_successful=False,
            reason='Blocked: Brute force detected and IP blacklisted'
        )
        db_session.add(new_attempt)
        db_session.commit()
        return jsonify({'message': 'Too many failed login attempts. Your IP has been blocked.'}), 403

    # --- Authenticate User (Non-Admin or Admin with incorrect credentials) ---
    # if user and check_password_hash(user.password_hash, password):
    if user and (user.password_hash == password): # Keeping your plain text password check here for consistency
        # Successful login
        new_attempt = LoginAttempt(
            email=gmail,
            ip_address=ip_address,
            is_successful=True,
            user_id=user.user_id,
            reason='Successful Login'
        )
        db_session.add(new_attempt)
        db_session.commit()

        # Set session variables for logged-in user
        session['user_id'] = user.user_id
        session['email'] = user.email
        session['is_admin'] = user.is_admin

        if user.is_admin:
            return jsonify({'message': 'Login successful!', 'redirect': url_for('admin_dashboard')})
        else:
            return jsonify({'message': 'Login successful!', 'redirect': url_for('user_dashboard')})
    else:
        # Failed login (incorrect password or user not found)
        reason = 'Incorrect Password' if user else 'User Not Found'
        new_attempt = LoginAttempt(
            email=gmail,
            ip_address=ip_address,
            is_successful=False,
            user_id=user.user_id if user else None,
            reason=reason
        )
        db_session.add(new_attempt)
        db_session.commit()

        if not user:
            unknown_user_attempts = db_session.query(LoginAttempt).filter(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.is_successful == False,
                LoginAttempt.user_id == None,
                LoginAttempt.attempt_time >= time_threshold
            ).count()

            if unknown_user_attempts >= FAILED_ATTEMPT_THRESHOLD / 2:
                admin_notification = Notification(
                    admin_email='admin@yourdomain.com',
                    notification_type='Suspicious Unknown User Attempts',
                    message=f'Multiple attempts ({unknown_user_attempts + 1}) to log in with unknown emails from IP {ip_address}.',
                    related_ip=ip_address
                )
                db_session.add(admin_notification)
                db_session.commit()
                print(f"ADMIN ALERT: Suspicious unknown user attempts from IP {ip_address}.")

        return jsonify({'message': 'Invalid email or password.'}), 401

@app.route('/dashboard')
@login_required
def user_dashboard():
    """Simple dashboard for regular users."""
    return render_template('dashboard.html', email=session.get('email'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard showing security logs."""
    # Fetch all data for display
    all_login_attempts = db_session.query(LoginAttempt).order_by(LoginAttempt.attempt_time.desc()).all()
    all_blacklisted_ips = db_session.query(BlacklistedIP).order_by(BlacklistedIP.blacklisted_at.desc()).all()
    all_notifications = db_session.query(Notification).order_by(Notification.sent_at.desc()).all()

    # Get counts for the admin dashboard
    total_users = db_session.query(User).count()
    total_blacklisted = db_session.query(BlacklistedIP).filter_by(is_active=True).count()
    total_failed_logins_today = db_session.query(LoginAttempt).filter(
        LoginAttempt.is_successful == False,
        LoginAttempt.attempt_time >= datetime.now() - timedelta(days=1)
    ).count()

    return render_template(
        'admin_dashboard.html',
        email=session.get('email'),
        login_attempts=all_login_attempts,
        blacklisted_ips=all_blacklisted_ips,
        notifications=all_notifications,
        total_users=total_users,
        total_blacklisted=total_blacklisted,
        total_failed_logins_today=total_failed_logins_today
    )

@app.route('/logout')
@login_required
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Add a tear down context to remove the session
@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

if __name__ == '__main__':
    app.run(debug=True) # Set debug=False in production