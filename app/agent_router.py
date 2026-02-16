from fastapi import APIRouter, Depends
from app.auth import require_user
from app.agent import run_soc_report

router = APIRouter()

@router.post("/agent/report/{upload_id}")
def agent_report(upload_id: str, user=Depends(require_user)):
    # MVP: synchronous
    return run_soc_report(upload_id)
