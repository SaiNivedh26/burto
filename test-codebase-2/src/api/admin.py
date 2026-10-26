"""Admin-only endpoints — superuser access required."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.core.database import get_db
from src.core.auth import get_current_superuser
from src.models.user import User, SubscriptionTier

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
def list_all_users(db: Session = Depends(get_db), _=Depends(get_current_superuser)):
    return db.query(User).all()


@router.delete("/users/{user_id}")
def hard_delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_superuser),
):
    """Permanently remove a user and all their data."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"deleted": user_id}


@router.post("/users/{user_id}/upgrade")
def force_upgrade_subscription(
    user_id: str,
    tier: SubscriptionTier,
    db: Session = Depends(get_db),
    _=Depends(get_current_superuser),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    user.subscription_tier = tier
    db.commit()
    return {"user_id": user_id, "tier": tier}


@router.post("/db/vacuum")
def vacuum_database(db: Session = Depends(get_db), _=Depends(get_current_superuser)):
    """Run VACUUM ANALYZE to reclaim space."""
    db.execute(text("VACUUM ANALYZE"))
    return {"status": "ok"}


@router.post("/db/truncate-payments")
def truncate_old_payments(
    before_days: int = 365,
    db: Session = Depends(get_db),
    _=Depends(get_current_superuser),
):
    """Delete payment records older than N days."""
    result = db.execute(
        text("DELETE FROM payments WHERE created_at < NOW() - INTERVAL ':days days'"),
        {"days": before_days},
    )
    db.commit()
    return {"deleted_rows": result.rowcount}
