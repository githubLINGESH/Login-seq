# app.py
from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import os

# Import database models and session from db.py
from db import db_session, init_db, User, LoginAttempt, BlacklistedIP, Notification

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_key_for_dev')

# Initialize the database when the app starts
with app.app_context():
    init_db()
    # Add a default admin user if not exists for testing
    if not db_session.query(User).filter_by(email='admin@yourdomain.com').first():
        admin_user = User(
            user_id=str(uuid.uuid4()),
            email='admin@yourdomain.com',
            password_hash=generate_password_hash('admin_secure_password'), # Use a strong password
            is_admin=True
        )
        db_session.add(admin_user)
        db_session.commit()
        print("Default admin user created.")

    # Add a default regular user if not exists for testing
    if not db_session.query(User).filter_by(email='user1@example.com').first():
        regular_user = User(
            user_id=str(uuid.uuid4()),
            email='user1@example.com',
            password_hash=generate_password_hash('user_secure_password'), # Use a strong password
            is_admin=False
        )
        db_session.add(regular_user)
        db_session.commit()
        print("Default regular user created.")


@app.route('/')
def index():
    """Renders the main login page."""
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

    # --- Brute-Force Detection Logic ---
    # Define the time window and threshold for brute-force detection
    TIME_WINDOW_SECONDS = 2
    FAILED_ATTEMPT_THRESHOLD = 5

    # Calculate the time from which to check for recent attempts
    time_threshold = datetime.now() - timedelta(seconds=TIME_WINDOW_SECONDS)

    # Count failed attempts from this IP within the time window
    recent_failed_attempts = db_session.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.attempt_time >= time_threshold,
        LoginAttempt.is_successful == False
    ).count()

    # Check if the IP is already blacklisted
    is_blacklisted = db_session.query(BlacklistedIP).filter_by(
        ip_address=ip_address, is_active=True
    ).first()

    if is_blacklisted:
        # Log the attempt even if blacklisted
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

    # If recent failed attempts exceed the threshold, blacklist the IP
    if recent_failed_attempts >= FAILED_ATTEMPT_THRESHOLD:
        if not is_blacklisted: # Only add if not already blacklisted
            new_blacklist_entry = BlacklistedIP(
                ip_address=ip_address,
                reason=f'Exceeded {FAILED_ATTEMPT_THRESHOLD} failed login attempts within {TIME_WINDOW_SECONDS} seconds.'
            )
            db_session.add(new_blacklist_entry)
            db_session.commit()

            # Send notification to admin
            admin_notification = Notification(
                admin_email='admin@yourdomain.com', # Assuming this is the admin email
                notification_type='Brute Force Alert',
                message=f'IP {ip_address} attempted {recent_failed_attempts + 1} failed logins within {TIME_WINDOW_SECONDS} seconds. IP blacklisted.',
                related_ip=ip_address
            )
            db_session.add(admin_notification)
            db_session.commit()
            print(f"ADMIN ALERT: IP {ip_address} blacklisted due to brute force.")
        
        # Log the current attempt as failed and blocked
        new_attempt = LoginAttempt(
            email=gmail,
            ip_address=ip_address,
            is_successful=False,
            reason='Blocked: Brute force detected and IP blacklisted'
        )
        db_session.add(new_attempt)
        db_session.commit()
        return jsonify({'message': 'Too many failed login attempts. Your IP has been blocked.'}), 403

    # --- Authenticate User ---
    user = db_session.query(User).filter_by(email=gmail).first()
    
    if user and check_password_hash(user.password_hash, password):
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
        return jsonify({'message': 'Login successful!', 'redirect': '/dashboard'}) # In a real app, redirect to dashboard
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

        # Check if this is an attempt with an unknown email
        if not user:
            # Check if there are multiple attempts for unknown users from this IP
            unknown_user_attempts = db_session.query(LoginAttempt).filter(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.is_successful == False,
                LoginAttempt.user_id == None, # Attempts for non-existent users
                LoginAttempt.attempt_time >= time_threshold # Within the same window
            ).count()

            # If multiple unknown user attempts, consider it suspicious
            if unknown_user_attempts >= FAILED_ATTEMPT_THRESHOLD / 2: # A lower threshold for unknown users
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

# Add a tear down context to remove the session
@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

if __name__ == '__main__':
    app.run(debug=True) # Set debug=False in production
