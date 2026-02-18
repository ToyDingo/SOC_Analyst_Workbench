# app/storage.py
import os
from pathlib import Path
from typing import Optional

def is_gcp() -> bool:
    # Cloud Run sets K_SERVICE
    return bool(os.getenv("K_SERVICE")) or os.getenv("ENV") in ("prod", "gcp")

def get_local_upload_dir() -> Path:
    # Local: mount ./uploads into container OR use /tmp/uploads in Cloud Run if needed
    p = Path(os.getenv("UPLOAD_DIR", "/app/uploads"))
    p.mkdir(parents=True, exist_ok=True)
    return p

def get_gcs_bucket() -> Optional[str]:
    return os.getenv("GCS_BUCKET") or None
