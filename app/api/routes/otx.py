from fastapi import APIRouter
from pydantic import BaseModel
from app.core.pipeline import run_otx_sync
import threading

router = APIRouter(prefix="/otx", tags=["OTX"])

class OTXConfig(BaseModel):
    api_key: str

@router.post("/sync")
def sync_otx(body: OTXConfig):
    thread = threading.Thread(
        target=run_otx_sync,
        args=(body.api_key,),
        daemon=True
    )
    thread.start()
    return {"status": "OTX sync started"}

@router.post("/test")
def test_otx(body: OTXConfig):
    from app.core.otx_client import OTXClient
    client = OTXClient(body.api_key)
    success = client.test_connection()
    return {"success": success, "message": "Connected to OTX" if success else "Failed"}
