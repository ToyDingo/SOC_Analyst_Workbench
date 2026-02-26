""" This module contains the authentication logic, including password hashing, 
JWT token creation and verification, and a dependency function to require 
authentication for protected endpoints. 

Accessed by main.py for user registration, login, and protected endpoints."""

import os
import time
import jwt

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))
bearer_scheme = HTTPBearer()
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

#--------------------------------------------------------
# Helper Functions used for authentication
#--------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_access_token(user_id: str, email: str) -> str:
    now = int(time.time())
    exp = now + JWT_EXPIRES_MINUTES * 60
    payload = {
        "sub": user_id,
        "email": email,
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_user(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    return decode_token(creds.credentials)