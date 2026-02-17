import os
import uuid
import psycopg

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pathlib import Path
from app.auth import require_user, create_access_token, hash_password, verify_password
from app.analysis import router as analysis_router
from app.ingest import run_ingest_job
from app.detect import router as detect_router
from app.agent_router import router as agent_router
from app.db import connect_db

app = FastAPI()
app.include_router(analysis_router)
app.include_router(detect_router)
app.include_router(agent_router)

DATABASE_URL = os.getenv("DATABASE_URL")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "5000000"))  # 5MB
CHUNK_SIZE = 1024 * 1024  # 1MB\

# Local -----------------------------------------
#UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/app/uploads"))
#UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
# GCP ------------------------------------------
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

#-----API Endpoints-----#
@app.get("/play/{name}/{age}")
def play(name: str, age: int):
    return {"message": f"Your name is {name} and you are {age} year(s) old."}

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/")
def root():
    return {"message": "Hello from FastAPI in Docker"}

@app.post("/upload")
async def upload(
    bg: BackgroundTasks,
    file: UploadFile = File(...),
    user=Depends(require_user),
):
    upload_id = str(uuid.uuid4())
    filename = file.filename or "unknown"
    content_type = file.content_type
    user_id = user["sub"]

    stored_path = UPLOAD_DIR / f"{upload_id}__{filename}"

    # stream to disk (no full RAM read)
    size_bytes = 0
    with stored_path.open("wb") as out:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            size_bytes += len(chunk)
            if size_bytes > MAX_UPLOAD_BYTES:
                stored_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File too large")
            out.write(chunk)

     # create upload row
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO uploads (id, user_id, filename, content_type, size_bytes)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (upload_id, user_id, filename, content_type, size_bytes),
            )

    # create ingest job row
    ingest_job_id = str(uuid.uuid4())
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ingest_jobs (id, upload_id, user_id, status)
                VALUES (%s, %s, %s, %s)
                """,
                (ingest_job_id, upload_id, user_id, "queued"),
            )

    # run ingestion in background immediately
    bg.add_task(run_ingest_job, ingest_job_id, upload_id, str(stored_path))

    return {
        "id": upload_id,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "stored_path": str(stored_path),
        "ingest_job_id": ingest_job_id,
        "ingest_status": "queued",
    }

@app.post("/auth/register")
def register(req: RegisterRequest):
    user_id = str(uuid.uuid4())
    email = req.email.lower().strip()
    password_hash = hash_password(req.password)

    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (id, email, password_hash)
                    VALUES (%s, %s, %s)
                    """,
                    (user_id, email, password_hash),
                )
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Email already registered")

    return {"id": user_id, "email": email}

@app.post("/auth/login")
def login(req: LoginRequest):
    email = req.email.lower().strip()

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, password_hash FROM users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id, password_hash = row
    if not verify_password(req.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(str(user_id), email)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/auth/me")
def me(user=Depends(require_user)):
    # user is the decoded JWT payload
    return {"user_id": user["sub"], "email": user.get("email")}

@app.post("/ingest/{upload_id}")
def start_ingest(upload_id: str, bg: BackgroundTasks, user=Depends(require_user)):
    user_id = user["sub"]

    # find upload row + enforce ownership
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select id, user_id, filename from uploads where id=%s",
                (upload_id,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")
    if str(row[1]) != str(user_id):
        raise HTTPException(status_code=403, detail="Forbidden")

    # locate stored file (matches upload naming scheme)
    filename = row[2]
    stored_path = UPLOAD_DIR / f"{upload_id}__{filename}"
    if not stored_path.exists():
        raise HTTPException(status_code=500, detail="Stored file missing on disk")

    job_id = str(uuid.uuid4())
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ingest_jobs (id, upload_id, user_id, status)
                VALUES (%s, %s, %s, %s)
                """,
                (job_id, upload_id, user_id, "queued"),
            )

    # run ingestion in background
    bg.add_task(run_ingest_job, job_id, upload_id, str(stored_path))

    return {"job_id": job_id, "upload_id": upload_id, "status": "queued"}


@app.get("/ingest/{job_id}")
def get_ingest(job_id: str, user=Depends(require_user)):
    user_id = user["sub"]

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, upload_id, user_id, status, inserted_events, bad_lines, error, created_at, updated_at
                from ingest_jobs
                where id=%s
                """,
                (job_id,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Ingest job not found")
    if str(row[2]) != str(user_id):
        raise HTTPException(status_code=403, detail="Forbidden")

    return {
        "job_id": str(row[0]),
        "upload_id": str(row[1]),
        "status": row[3],
        "inserted_events": int(row[4] or 0),
        "bad_lines": int(row[5] or 0),
        "error": row[6],
        "created_at": row[7].isoformat() if row[7] else None,
        "updated_at": row[8].isoformat() if row[8] else None,
    }

@app.get("/features/{upload_id}")
def get_features(upload_id: str, user=Depends(require_user)):
    user_id = user["sub"]

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("select user_id from uploads where id=%s", (upload_id,))
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")
    if str(row[0]) != str(user_id):
        raise HTTPException(status_code=403, detail="Forbidden")

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("select stats from upload_features where upload_id=%s", (upload_id,))
            row2 = cur.fetchone()

    if not row2:
        return {"stats": {}}

    return {"stats": row2[0]}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    #allow_origins=["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
