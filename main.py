from fastapi import FastAPI, HTTPException, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import os
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Update Manager API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security configuration
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Dummy user database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
    }
}

# Security utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    if username in fake_users_db:
        user_dict = fake_users_db[username]
        return user_dict

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    return {"message": "Successfully logged out"}

@app.get("/download/exe")
async def download_exe(current_user: dict = Depends(get_current_user)):
    try:
        # Look for the installer in the current directory
        installer_path = Path("app.exe")
        logger.info(f"Attempting to download installer from: {installer_path.absolute()}")
        
        if not installer_path.exists():
            logger.error(f"Installer not found at: {installer_path.absolute()}")
            raise HTTPException(
                status_code=404,
                detail="Installer not found. Please upload the installer first."
            )
        
        if not installer_path.is_file():
            logger.error(f"Path exists but is not a file: {installer_path.absolute()}")
            raise HTTPException(
                status_code=500,
                detail="Installer path is not a valid file."
            )
        
        file_size = installer_path.stat().st_size
        logger.info(f"Installer file size: {file_size} bytes")
        
        return FileResponse(
            path=str(installer_path),
            filename="app.exe",
            media_type="application/vnd.microsoft.windows.executable",
            headers={
                "Content-Disposition": 'attachment; filename="app.exe"',
                "Content-Type": "application/vnd.microsoft.windows.executable",
                "Content-Length": str(file_size)
            }
        )
    except Exception as e:
        logger.error(f"Error serving installer: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error serving installer: {str(e)}"
        )

@app.get("/")
async def root():
    return {"message": "Update Manager API is running"} 