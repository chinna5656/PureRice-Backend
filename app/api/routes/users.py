from fastapi import APIRouter, Depends
from app.api.deps import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("/me")
def read_me(user: str = Depends(get_current_user)):
    return {"username": user}
