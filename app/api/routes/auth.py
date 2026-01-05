from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from app.core.security import create_access_token, verify_password
from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(prefix="/auth", tags=["Auth"])

# mock user
fake_user = {
    "username": "admin",
    "password": "$2b$12$..."  # bcrypt hash
}

@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    if form.username != fake_user["username"]:
        raise HTTPException(status_code=401)

    if not verify_password(form.password, fake_user["password"]):
        raise HTTPException(status_code=401)

    token = create_access_token(
        {"sub": form.username},
        ACCESS_TOKEN_EXPIRE_MINUTES
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }
