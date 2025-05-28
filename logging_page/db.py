# db.py
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import sessionmaker, relationship, scoped_session # Import scoped_session
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid
import os

# --- MySQL Connection Details ---
MYSQL_HOST = "novagrid-de003-novagrid-dbde003.l.aivencloud.com"
MYSQL_PORT = "26648" # Default Aiven MySQL port example, check your dashboard
MYSQL_DATABASE = "defaultdb"
MYSQL_USER = "avnadmin"
MYSQL_PASSWORD = "AVNS_dH5fvp5tsTg3aTCNq8Y"


DATABASE_URL = (
    f"mysql+mysqlconnector://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Base class for declarative models
# For SQLAlchemy 2.0, you would typically use: from sqlalchemy.orm import declarative_base
Base = declarative_base()

# Define the database models (no changes here)

class User(Base):
    """Represents a user in the system."""
    __tablename__ = 'users'
    user_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    login_attempts = relationship('LoginAttempt', back_populates='user', lazy=True)

    def __repr__(self):
        return f"<User(email='{self.email}', is_admin={self.is_admin})>"

class LoginAttempt(Base):
    """Tracks every login attempt, successful or failed."""
    __tablename__ = 'login_attempts'
    attempt_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)
    attempt_time = Column(DateTime, default=datetime.utcnow)
    is_successful = Column(Boolean, nullable=False)
    user_id = Column(String(36), ForeignKey('users.user_id'), nullable=True)
    reason = Column(String(255))

    user = relationship('User', back_populates='login_attempts')

    def __repr__(self):
        return (f"<LoginAttempt(email='{self.email}', ip_address='{self.ip_address}', "
                f"successful={self.is_successful}, time='{self.attempt_time}')>")

class BlacklistedIP(Base):
    """Stores IP addresses that have been identified as malicious and should be blocked."""
    __tablename__ = 'blacklisted_ips'
    blacklist_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = Column(String(45), unique=True, nullable=False)
    blacklisted_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(String(255))
    is_active = Column(Boolean, default=True)

    def __repr__(self):
        return f"<BlacklistedIP(ip_address='{self.ip_address}', active={self.is_active})>"

class Notification(Base):
    """Logs security notifications sent to the admin."""
    __tablename__ = 'notifications'
    notification_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_email = Column(String(255), nullable=False)
    notification_type = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    related_ip = Column(String(45), nullable=True)
    related_user_id = Column(String(36), ForeignKey('users.user_id'), nullable=True)
    sent_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return (f"<Notification(type='{self.notification_type}', "
                f"admin='{self.admin_email}', sent_at='{self.sent_at}')>")

# Create a configured "Session" class
Session = sessionmaker(bind=engine)

# Create a Session object using scoped_session
# This is the crucial change:
db_session = scoped_session(Session)

def init_db():
    """Creates all tables in the database."""
    Base.metadata.create_all(bind=engine)
    print("Database tables created or already exist in MySQL.")

if __name__ == '__main__':
    init_db()
    print("MySQL database initialized successfully.")