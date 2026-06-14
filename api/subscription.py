"""
DEPRECATED shim — canonical subscription logic lives in api/subscription_store.py (B2).

This module previously held a parallel copy of the product-key / subscription logic that
was imported by nothing. To keep one source of truth (working agreement: consolidate
duplicates before extending), it now just re-exports the canonical store. Prefer importing
from ``subscription_store`` directly.

© 2024-2026 Ruthvik Bandari. All Rights Reserved.
"""

from subscription_store import (  # noqa: F401
    OWNER_EMAILS,
    SubscriptionStore,
    is_owner,
    subscriptions,
)


def create_product_key(subscription_type: str = "individual", validity_days: int = 365,
                       created_by: str = "admin") -> dict:
    return subscriptions.create_product_key(subscription_type, validity_days, created_by)


def validate_product_key(key: str) -> dict:
    return subscriptions.validate_product_key(key)


def activate_product_key(key: str, email: str) -> dict:
    return subscriptions.activate(key, email)


def check_subscription(email: str) -> dict:
    return subscriptions.check_subscription(email)
