"""
CTPPO Subscription & Product Key System
========================================
Handles user subscriptions, product key generation, and license validation.

© 2024-2026 Ruthvik Bandari. All Rights Reserved.
"""

import hashlib
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional
import json
import os

# Owner credentials (no subscription required)
OWNER_EMAILS = [
    "bandari.ru@northeastern.edu",
    "ruthvik299@gmail.com"
]

# In-memory storage (replace with database in production)
PRODUCT_KEYS_DB = {}
ACTIVATED_KEYS_DB = {}
USERS_DB = {}

def generate_product_key() -> str:
    """
    Generate a unique product key in format: CTPPO-XXXX-XXXX-XXXX-XXXX
    """
    chars = string.ascii_uppercase + string.digits
    segments = []
    for _ in range(4):
        segment = ''.join(secrets.choice(chars) for _ in range(4))
        segments.append(segment)
    return f"CTPPO-{'-'.join(segments)}"


def create_product_key(
    subscription_type: str = "individual",
    validity_days: int = 365,
    created_by: str = "admin"
) -> dict:
    """
    Create a new product key with subscription details.
    
    Args:
        subscription_type: "individual" or "enterprise"
        validity_days: Number of days the subscription is valid
        created_by: Admin who created the key
    
    Returns:
        Dictionary with product key details
    """
    key = generate_product_key()
    
    # Ensure unique key
    while key in PRODUCT_KEYS_DB:
        key = generate_product_key()
    
    key_data = {
        "key": key,
        "subscription_type": subscription_type,
        "validity_days": validity_days,
        "created_at": datetime.utcnow().isoformat(),
        "created_by": created_by,
        "is_activated": False,
        "activated_by": None,
        "activated_at": None,
        "expires_at": None
    }
    
    PRODUCT_KEYS_DB[key] = key_data
    return key_data


def validate_product_key(key: str) -> dict:
    """
    Validate a product key.
    
    Returns:
        Dictionary with validation result and details
    """
    if key not in PRODUCT_KEYS_DB:
        return {
            "valid": False,
            "error": "Invalid product key",
            "code": "INVALID_KEY"
        }
    
    key_data = PRODUCT_KEYS_DB[key]
    
    if key_data["is_activated"]:
        return {
            "valid": False,
            "error": "This product key has already been activated",
            "code": "ALREADY_ACTIVATED",
            "activated_by": key_data["activated_by"]
        }
    
    return {
        "valid": True,
        "subscription_type": key_data["subscription_type"],
        "validity_days": key_data["validity_days"]
    }


def activate_product_key(key: str, email: str) -> dict:
    """
    Activate a product key for a specific user.
    
    Args:
        key: The product key to activate
        email: User's email address
    
    Returns:
        Dictionary with activation result
    """
    # Check if user is owner (no activation needed)
    if email.lower() in [e.lower() for e in OWNER_EMAILS]:
        return {
            "success": True,
            "message": "Owner account - no activation required",
            "is_owner": True,
            "subscription_type": "owner",
            "expires_at": None
        }
    
    # Validate the key
    validation = validate_product_key(key)
    if not validation["valid"]:
        return {
            "success": False,
            "error": validation["error"],
            "code": validation["code"]
        }
    
    key_data = PRODUCT_KEYS_DB[key]
    
    # Activate the key
    expires_at = datetime.utcnow() + timedelta(days=key_data["validity_days"])
    
    key_data["is_activated"] = True
    key_data["activated_by"] = email
    key_data["activated_at"] = datetime.utcnow().isoformat()
    key_data["expires_at"] = expires_at.isoformat()
    
    # Store activation
    ACTIVATED_KEYS_DB[email.lower()] = {
        "key": key,
        "subscription_type": key_data["subscription_type"],
        "activated_at": key_data["activated_at"],
        "expires_at": key_data["expires_at"]
    }
    
    return {
        "success": True,
        "message": "Product key activated successfully",
        "subscription_type": key_data["subscription_type"],
        "expires_at": expires_at.isoformat(),
        "days_remaining": key_data["validity_days"]
    }


def check_subscription(email: str) -> dict:
    """
    Check if a user has an active subscription.
    
    Args:
        email: User's email address
    
    Returns:
        Dictionary with subscription status
    """
    email_lower = email.lower()
    
    # Check if owner
    if email_lower in [e.lower() for e in OWNER_EMAILS]:
        return {
            "has_subscription": True,
            "is_owner": True,
            "subscription_type": "owner",
            "expires_at": None,
            "days_remaining": float('inf'),
            "status": "active"
        }
    
    # Check activated keys
    if email_lower not in ACTIVATED_KEYS_DB:
        return {
            "has_subscription": False,
            "is_owner": False,
            "status": "no_subscription",
            "message": "No active subscription found. Please activate a product key."
        }
    
    activation = ACTIVATED_KEYS_DB[email_lower]
    expires_at = datetime.fromisoformat(activation["expires_at"])
    
    if datetime.utcnow() > expires_at:
        return {
            "has_subscription": False,
            "is_owner": False,
            "subscription_type": activation["subscription_type"],
            "expires_at": activation["expires_at"],
            "status": "expired",
            "message": "Your subscription has expired. Please renew."
        }
    
    days_remaining = (expires_at - datetime.utcnow()).days
    
    return {
        "has_subscription": True,
        "is_owner": False,
        "subscription_type": activation["subscription_type"],
        "expires_at": activation["expires_at"],
        "days_remaining": days_remaining,
        "status": "active"
    }


def is_owner(email: str) -> bool:
    """Check if email belongs to owner."""
    return email.lower() in [e.lower() for e in OWNER_EMAILS]


# Pre-generate some demo keys for testing
def initialize_demo_keys():
    """Create demo product keys for testing."""
    demo_keys = [
        create_product_key("individual", 30, "system"),  # 30-day trial
        create_product_key("individual", 365, "system"),  # 1-year individual
        create_product_key("enterprise", 365, "system"),  # 1-year enterprise
    ]
    return demo_keys


# FastAPI Routes for Subscription System
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr

subscription_router = APIRouter(prefix="/api/subscription", tags=["Subscription"])


class ProductKeyActivation(BaseModel):
    product_key: str
    email: EmailStr


class SubscriptionCheck(BaseModel):
    email: EmailStr


class GenerateKeyRequest(BaseModel):
    subscription_type: str = "individual"
    validity_days: int = 365
    admin_secret: str  # Required for generating keys


ADMIN_SECRET = os.getenv("ADMIN_SECRET", "ctppo-admin-2026")  # Change in production


@subscription_router.post("/activate")
async def activate_key(data: ProductKeyActivation):
    """Activate a product key for a user."""
    result = activate_product_key(data.product_key, data.email)
    
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return result


@subscription_router.post("/check")
async def check_user_subscription(data: SubscriptionCheck):
    """Check subscription status for a user."""
    return check_subscription(data.email)


@subscription_router.post("/validate-key")
async def validate_key(product_key: str):
    """Validate a product key without activating it."""
    return validate_product_key(product_key)


@subscription_router.post("/generate-key")
async def generate_key(data: GenerateKeyRequest):
    """Generate a new product key (admin only)."""
    if data.admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin credentials")
    
    key_data = create_product_key(
        subscription_type=data.subscription_type,
        validity_days=data.validity_days,
        created_by="admin"
    )
    
    return {
        "success": True,
        "product_key": key_data["key"],
        "subscription_type": key_data["subscription_type"],
        "validity_days": key_data["validity_days"]
    }


# Initialize demo keys on module load
_demo_keys = initialize_demo_keys()
print("=" * 60)
print("CTPPO - Demo Product Keys Generated:")
print("=" * 60)
for key in _demo_keys:
    print(f"  {key['key']} ({key['subscription_type']}, {key['validity_days']} days)")
print("=" * 60)
