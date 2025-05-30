# reset_test_data.py
from db import db_session, LoginAttempt, BlacklistedIP, Notification, User, init_db
import sys

def clear_table(model, table_name):
    """Deletes all records from a given table model."""
    print(f"Attempting to clear '{table_name}' table...")
    try:
        num_rows_deleted = db_session.query(model).delete(synchronize_session='fetch')
        db_session.commit()
        print(f"Successfully cleared {num_rows_deleted} rows from '{table_name}'.")
    except Exception as e:
        db_session.rollback()
        print(f"Error clearing '{table_name}' table: {e}")
        sys.exit(1) # Exit if critical tables can't be cleared

def reset_all_test_data():
    """Clears data from LoginAttempt, BlacklistedIP, and Notification tables."""
    print("\n--- Resetting Test Data ---")

    clear_table(LoginAttempt, 'login_attempts')
    clear_table(BlacklistedIP, 'blacklisted_ips')
    clear_table(Notification, 'notifications')

    print("\nTest data reset complete.")

if __name__ == '__main__':
    # Ensure the database connection is established and tables exist
    # This won't create tables if they already exist, just connects.
    init_db()

    reset_all_test_data()

    # It's crucial to remove the session after operations
    db_session.remove()
    print("Database session cleaned up.")

    print("\nRemember to run 'python populate_db.py' if you also need to reset user accounts.")