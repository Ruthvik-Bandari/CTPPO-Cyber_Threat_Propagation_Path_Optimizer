"""
CTPPO Database Module - Persistent Storage with Supabase PostgreSQL
"""
import os
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database URL from environment
DATABASE_URL = os.environ.get("DATABASE_URL")

# SQLAlchemy setup
Base = declarative_base()

# Create engine only if DATABASE_URL is set
engine = None
SessionLocal = None

if DATABASE_URL:
    try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ============================================================================
# MODELS
# ============================================================================

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_2fa_enabled = Column(Boolean, default=False)
    totp_secret = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class ProductKey(Base):
    __tablename__ = "product_keys"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(50), unique=True, nullable=False, index=True)
    subscription_type = Column(String(50), nullable=False)  # individual, enterprise, academic
    validity_days = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_used = Column(Boolean, default=False)
    used_by_email = Column(String(255), nullable=True)
    used_at = Column(DateTime, nullable=True)


class Subscription(Base):
    __tablename__ = "subscriptions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    product_key = Column(String(50), nullable=False)
    subscription_type = Column(String(50), nullable=False)
    activated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Create all tables if they don't exist"""
    if engine:
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created/verified")
    else:
        print("⚠️ No DATABASE_URL set, using in-memory storage")


def get_db():
    """Get database session"""
    if SessionLocal:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()
    else:
        yield None


# ============================================================================
# USER OPERATIONS
# ============================================================================

def db_create_user(email: str, name: str, hashed_password: str) -> Optional[dict]:
    """Create a new user in database"""
    if not SessionLocal:
        return None
    
    db = SessionLocal()
    try:
        user = User(
            email=email.lower(),
            name=name,
            hashed_password=hashed_password
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return {
            "email": user.email,
            "name": user.name,
            "is_2fa_enabled": user.is_2fa_enabled,
            "created_at": user.created_at.isoformat() if user.created_at else None
        }
    except Exception as e:
        db.rollback()
        print(f"Error creating user: {e}")
        return None
    finally:
        db.close()


def db_get_user(email: str) -> Optional[dict]:
    """Get user by email"""
    if not SessionLocal:
        return None
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email.lower()).first()
        if user:
            return {
                "email": user.email,
                "name": user.name,
                "hashed_password": user.hashed_password,
                "is_2fa_enabled": user.is_2fa_enabled,
                "totp_secret": user.totp_secret,
                "created_at": user.created_at.isoformat() if user.created_at else None
            }
        return None
    finally:
        db.close()


def db_update_user(email: str, updates: dict) -> bool:
    """Update user fields"""
    if not SessionLocal:
        return False
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email.lower()).first()
        if user:
            for key, value in updates.items():
                if hasattr(user, key):
                    setattr(user, key, value)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        print(f"Error updating user: {e}")
        return False
    finally:
        db.close()


def db_user_exists(email: str) -> bool:
    """Check if user exists"""
    if not SessionLocal:
        return False
    
    db = SessionLocal()
    try:
        return db.query(User).filter(User.email == email.lower()).first() is not None
    finally:
        db.close()


# ============================================================================
# PRODUCT KEY OPERATIONS
# ============================================================================

def db_create_product_key(key: str, subscription_type: str, validity_days: int) -> Optional[dict]:
    """Create a new product key"""
    if not SessionLocal:
        return None
    
    db = SessionLocal()
    try:
        product_key = ProductKey(
            key=key,
            subscription_type=subscription_type,
            validity_days=validity_days
        )
        db.add(product_key)
        db.commit()
        db.refresh(product_key)
        return {
            "key": product_key.key,
            "subscription_type": product_key.subscription_type,
            "validity_days": product_key.validity_days,
            "created_at": product_key.created_at.isoformat() if product_key.created_at else None,
            "is_used": product_key.is_used
        }
    except Exception as e:
        db.rollback()
        print(f"Error creating product key: {e}")
        return None
    finally:
        db.close()


def db_get_product_key(key: str) -> Optional[dict]:
    """Get product key by key string"""
    if not SessionLocal:
        return None
    
    db = SessionLocal()
    try:
        pk = db.query(ProductKey).filter(ProductKey.key == key).first()
        if pk:
            return {
                "key": pk.key,
                "subscription_type": pk.subscription_type,
                "validity_days": pk.validity_days,
                "created_at": pk.created_at.isoformat() if pk.created_at else None,
                "is_used": pk.is_used,
                "used_by_email": pk.used_by_email
            }
        return None
    finally:
        db.close()


def db_get_all_product_keys() -> list:
    """Get all product keys"""
    if not SessionLocal:
        return []
    
    db = SessionLocal()
    try:
        keys = db.query(ProductKey).all()
        return [{
            "key": pk.key,
            "subscription_type": pk.subscription_type,
            "validity_days": pk.validity_days,
            "created_at": pk.created_at.isoformat() if pk.created_at else None,
            "used": pk.is_used,
            "used_by": pk.used_by_email
        } for pk in keys]
    finally:
        db.close()


def db_mark_key_used(key: str, email: str) -> bool:
    """Mark a product key as used"""
    if not SessionLocal:
        return False
    
    db = SessionLocal()
    try:
        pk = db.query(ProductKey).filter(ProductKey.key == key).first()
        if pk:
            pk.is_used = True
            pk.used_by_email = email.lower()
            pk.used_at = datetime.now(timezone.utc)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        print(f"Error marking key used: {e}")
        return False
    finally:
        db.close()


def db_delete_product_key(key: str) -> bool:
    """Delete a product key"""
    if not SessionLocal:
        return False
    
    db = SessionLocal()
    try:
        pk = db.query(ProductKey).filter(ProductKey.key == key).first()
        if pk:
            db.delete(pk)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        return False
    finally:
        db.close()


# ============================================================================
# SUBSCRIPTION OPERATIONS
# ============================================================================

def db_create_subscription(email: str, product_key: str, subscription_type: str, expires_at: datetime) -> Optional[dict]:
    """Create a new subscription"""
    if not SessionLocal:
        return None
    
    db = SessionLocal()
    try:
        # Remove existing subscription if any
        existing = db.query(Subscription).filter(Subscription.email == email.lower()).first()
        if existing:
            db.delete(existing)
        
        subscription = Subscription(
            email=email.lower(),
            product_key=product_key,
            subscription_type=subscription_type,
            expires_at=expires_at
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        return {
            "email": subscription.email,
            "subscription_type": subscription.subscription_type,
            "activated_at": subscription.activated_at.isoformat() if subscription.activated_at else None,
            "expires_at": subscription.expires_at.isoformat() if subscription.expires_at else None
        }
    except Exception as e:
        db.rollback()
        print(f"Error creating subscription: {e}")
        return None
    finally:
        db.close()


def db_get_subscription(email: str) -> Optional[dict]:
    """Get subscription by email"""
    if not SessionLocal:
        return None
    
    db = SessionLocal()
    try:
        sub = db.query(Subscription).filter(Subscription.email == email.lower()).first()
        if sub:
            return {
                "email": sub.email,
                "product_key": sub.product_key,
                "subscription_type": sub.subscription_type,
                "activated_at": sub.activated_at.isoformat() if sub.activated_at else None,
                "expires_at": sub.expires_at.isoformat() if sub.expires_at else None
            }
        return None
    finally:
        db.close()


def db_get_all_subscriptions() -> list:
    """Get all active subscriptions"""
    if not SessionLocal:
        return []
    
    db = SessionLocal()
    try:
        subs = db.query(Subscription).all()
        return [{
            "email": sub.email,
            "subscription_type": sub.subscription_type,
            "activated_at": sub.activated_at.isoformat() if sub.activated_at else None,
            "expires_at": sub.expires_at.isoformat() if sub.expires_at else None
        } for sub in subs]
    finally:
        db.close()


def db_delete_subscription(email: str) -> bool:
    """Delete a subscription"""
    if not SessionLocal:
        return False
    
    db = SessionLocal()
    try:
        sub = db.query(Subscription).filter(Subscription.email == email.lower()).first()
        if sub:
            db.delete(sub)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        return False
    finally:
        db.close()


# ============================================================================
# HELPER FUNCTION
# ============================================================================

def is_db_available() -> bool:
    """Check if database is available"""
    return SessionLocal is not None
