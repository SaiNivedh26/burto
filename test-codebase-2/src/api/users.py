from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.db.connection import get_db
from src.db.models import User
from src.auth.jwt import create_access_token, verify_token

router = APIRouter(prefix="/users", tags=["users"])

@router.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # TODO: verify hashed password properly
    token = create_access_token({"sub": str(user.id), "email": user.email})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me")
def get_current_user(token: str, db: Session = Depends(get_db)):
    payload = verify_token(token)
    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "email": user.email, "is_active": user.is_active}
