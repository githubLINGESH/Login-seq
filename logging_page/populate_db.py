# populate_db.py
from db import db_session, User, LoginAttempt, BlacklistedIP, Notification, init_db
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime

def add_initial_users():
    """
    Adds initial regular users and an admin user to the database.
    Checks if users already exist to prevent duplicates.
    Ensures a minimum of 10 users (1 admin + 9 regular).
    """
    print("--- Adding Initial Users ---")

    # Admin User
    admin_email = "admin@yourdomain.com"
    if not db_session.query(User).filter_by(email=admin_email).first():
        admin_user = User(
            user_id=str(uuid.uuid4()),
            email=admin_email,
            password_hash=generate_password_hash("admin_secure_password_123"), # IMPORTANT: Use a strong password
            is_admin=True
        )
        db_session.add(admin_user)
        print(f"Added admin user: {admin_email}")
    else:
        print(f"Admin user '{admin_email}' already exists. Skipping.")

    # Regular User 1 (existing from previous version)
    user1_email = "user1@example.com"
    if not db_session.query(User).filter_by(email=user1_email).first():
        user1 = User(
            user_id=str(uuid.uuid4()),
            email=user1_email,
            password_hash=generate_password_hash("user_password_123"),
            is_admin=False
        )
        db_session.add(user1)
        print(f"Added regular user: {user1_email}")
    else:
        print(f"Regular user '{user1_email}' already exists. Skipping.")

    # Regular User 2 (existing from previous version)
    user2_email = "user2@example.com"
    if not db_session.query(User).filter_by(email=user2_email).first():
        user2 = User(
            user_id=str(uuid.uuid4()),
            email=user2_email,
            password_hash=generate_password_hash("another_user_pass"),
            is_admin=False
        )
        db_session.add(user2)
        print(f"Added regular user: {user2_email}")
    else:
        print(f"Regular user '{user2_email}' already exists. Skipping.")

    # Add 7 more regular users to reach a minimum of 10 (1 admin + 9 regular)
    # Total users will be 1 (admin) + 2 (user1, user2) + 7 (new_user_3 to new_user_9) = 10 users
    for i in range(3, 10): # Loop from 3 to 9 for user_3 to user_9
        new_user_email = f"user{i}@example.com"
        if not db_session.query(User).filter_by(email=new_user_email).first():
            new_user = User(
                user_id=str(uuid.uuid4()),
                email=new_user_email,
                password_hash=generate_password_hash(f"password_for_user{i}"),
                is_admin=False
            )
            db_session.add(new_user)
            print(f"Added regular user: {new_user_email}")
        else:
            print(f"Regular user '{new_user_email}' already exists. Skipping.")

    try:
        db_session.commit()
        print("Initial users committed successfully.")
    except Exception as e:
        db_session.rollback()
        print(f"Error committing initial users: {e}")

def verify_data():
    """
    Queries each table and prints its contents to verify data addition.
    """
    print("\n--- Verifying Data in Tables ---")

    # Verify Users
    print("\n--- Users Table ---")
    users = db_session.query(User).all()
    if users:
        print(f"Total users found: {len(users)}")
        for user in users:
            print(f"User ID: {user.user_id}, Email: {user.email}, Is Admin: {user.is_admin}, Created At: {user.created_at}")
            # You can also check a password (for verification purposes, not in production)
            # For example, to check 'user1@example.com' with 'user_password_123'
            if user.email == "user1@example.com":
                if check_password_hash(user.password_hash, "user_password_123"):
                    print(f"  Password check for {user.email}: SUCCESS")
                else:
                    print(f"  Password check for {user.email}: FAILED (This should not happen if added correctly)")
    else:
        print("No users found in the database.")

    # Verify LoginAttempts (will be empty initially unless app.py was run)
    print("\n--- LoginAttempts Table ---")
    attempts = db_session.query(LoginAttempt).all()
    if attempts:
        for attempt in attempts:
            print(f"Attempt ID: {attempt.attempt_id}, Email: {attempt.email}, IP: {attempt.ip_address}, Success: {attempt.is_successful}, Reason: {attempt.reason}, Time: {attempt.attempt_time}")
    else:
        print("No login attempts found in the database (expected if app.py hasn't run logins).")

    # Verify BlacklistedIPs (will be empty initially unless app.py was run)
    print("\n--- BlacklistedIPs Table ---")
    blacklisted_ips = db_session.query(BlacklistedIP).all()
    if blacklisted_ips:
        for ip in blacklisted_ips:
            print(f"Blacklist ID: {ip.blacklist_id}, IP: {ip.ip_address}, Reason: {ip.reason}, Active: {ip.is_active}, Blacklisted At: {ip.blacklisted_at}")
    else:
        print("No blacklisted IPs found in the database (expected if no attacks yet).")

    # Verify Notifications (will be empty initially unless app.py was run)
    print("\n--- Notifications Table ---")
    notifications = db_session.query(Notification).all()
    if notifications:
        for notif in notifications:
            print(f"Notification ID: {notif.notification_id}, Type: {notif.notification_type}, Admin: {notif.admin_email}, Message: {notif.message}, Sent At: {notif.sent_at}")
    else:
        print("No notifications found in the database (expected if no alerts yet).")


if __name__ == '__main__':
    # 1. Initialize the database (creates tables if they don't exist)
    init_db()

    # 2. Add initial users
    add_initial_users()

    # 3. Verify the data
    verify_data()

    # 4. Clean up the session
    db_session.remove()
    print("\nDatabase population and verification script finished.")
