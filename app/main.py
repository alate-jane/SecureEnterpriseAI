import os
import time
import shutil
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.config import settings
from app.core.security import (
    SecurityEngine,
    USERS_DB,
    create_access_token,
    verify_access_token,
)
from app.core.rag_engine import RAGEngine
from app.core.eval_engine import EvalEngine

app = FastAPI(
    title="Secure Enterprise AI Assistant",
    description="Production-grade RAG and Governance Pipeline for Engineering and Enterprise Workflows",
    version="1.1.0"
)

# Initialize engines
rag = RAGEngine()

# --- Auth Models & Dependencies ---

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    username: str
    display_name: str
    role: str

def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """Extracts user from bearer token. Defaults to guest if no token provided."""
    if not authorization or not authorization.startswith("Bearer "):
        return {"username": "guest", "display_name": "Guest Visitor", "role": "guest"}
    token = authorization.split(" ")[1]
    payload = verify_access_token(token)
    if not payload:
        return {"username": "guest", "display_name": "Guest Visitor", "role": "guest"}
    username = payload.get("sub")
    user = USERS_DB.get(username)
    if not user:
        return {"username": "guest", "display_name": "Guest Visitor", "role": "guest"}
    return user

def require_admin(current_user: dict = Depends(get_current_user)):
    """Ensures caller has admin privileges; otherwise returns 403 Forbidden."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access Denied: Administrative privileges required to manage enterprise documents."
        )
    return current_user

# --- Authentication Endpoints ---

@app.post("/api/auth/login", response_model=LoginResponse)
def login(creds: LoginRequest):
    user = USERS_DB.get(creds.username)
    if not user or user["password"] != creds.password:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = create_access_token(user["username"], user["role"])
    return LoginResponse(
        token=token,
        username=user["username"],
        display_name=user["display_name"],
        role=user["role"]
    )

@app.get("/api/auth/me")
def get_profile(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "display_name": current_user["display_name"],
        "role": current_user["role"],
        "is_authenticated": current_user["role"] != "guest"
    }

# --- Core Query Endpoints ---

class QueryRequest(BaseModel):
    query: str
    user_role: Optional[str] = None

class QueryResponse(BaseModel):
    answer: str
    citations: List[dict]
    grounded: bool
    faithfulness_score: float
    security_audit: dict
    latency_ms: float

@app.post("/api/query", response_model=QueryResponse)
def handle_query(req: QueryRequest, current_user: dict = Depends(get_current_user)):
    start_time = time.time()

    # Determine role: verified authenticated role takes precedence, else guest
    effective_role = current_user["role"]
    if effective_role == "guest" and req.user_role:
        # If guest chooses to simulate lower clearance, allow guest only
        effective_role = "guest"

    # Step 1: Prompt Injection Defense
    is_safe, injection_reason = SecurityEngine.inspect_prompt_injection(req.query)
    if not is_safe:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Security Policy Violation",
                "reason": injection_reason,
                "action": "Query terminated before reaching model execution layer."
            }
        )

    # Step 2: PII Redaction
    sanitized_query, pii_redactions = SecurityEngine.redact_pii(req.query)

    # Step 3: RBAC Clearance Filter
    rbac_filter = SecurityEngine.build_rbac_filter(effective_role)

    # Step 4: Vector Retrieval
    context_chunks = rag.retrieve(sanitized_query, rbac_filter=rbac_filter, top_k=3)

    # Step 5: Grounded Synthesis
    generation = rag.generate_grounded_response(sanitized_query, context_chunks)

    # Step 6: Automated Evaluation / Faithfulness Metric
    eval_result = EvalEngine.evaluate_faithfulness(generation["answer"], context_chunks)

    latency = round((time.time() - start_time) * 1000, 2)

    return QueryResponse(
        answer=generation["answer"],
        citations=generation["citations"],
        grounded=generation["grounded"],
        faithfulness_score=eval_result.get("faithfulness_score", 1.0),
        security_audit={
            "injection_status": "Clean",
            "pii_redacted": pii_redactions,
            "role_used": effective_role,
            "allowed_classifications": SecurityEngine.get_allowed_classifications(effective_role),
            "authenticated_as": current_user["display_name"]
        },
        latency_ms=latency
    )

# --- Admin Document Management (Protected by require_admin) ---

@app.get("/api/admin/documents")
def list_documents(admin_user: dict = Depends(require_admin)):
    """Returns all indexed enterprise documents in ChromaDB."""
    return {
        "documents": rag.list_indexed_documents(),
        "total_vectors": rag.collection.count()
    }

@app.delete("/api/admin/documents/{filename}")
def delete_document(filename: str, admin_user: dict = Depends(require_admin)):
    """Deletes all chunks of a specific document from vector store."""
    deleted_chunks = rag.delete_document(filename)
    return {
        "status": "success",
        "deleted_filename": filename,
        "deleted_chunks": deleted_chunks,
        "remaining_vectors": rag.collection.count()
    }

@app.post("/api/admin/upload")
async def upload_document(
    file: UploadFile = File(...),
    classification: str = Form("internal"),
    admin_user: dict = Depends(require_admin)
):
    """Uploads and embeds a document. Restricted to Admin."""
    upload_dir = "./data/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    if file.filename.lower().endswith(".pdf"):
        chunk_count = rag.ingest_pdf(file_path, classification=classification)
    else:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        chunk_count = rag.ingest_raw_text(file.filename, text, classification=classification)

    return {
        "filename": file.filename,
        "classification": classification,
        "chunks_indexed": chunk_count,
        "total_store_vectors": rag.collection.count()
    }

@app.post("/api/admin/reset")
def reset_database(admin_user: dict = Depends(require_admin)):
    """Purges the ChromaDB collection completely."""
    rag.reset_knowledge_base()
    return {
        "status": "success",
        "message": "Vector database has been wiped clean.",
        "vectors_remaining": 0
    }

# --- System & Eval Endpoints ---

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "provider": settings.llm_provider,
        "indexed_documents_count": rag.collection.count()
    }

@app.get("/api/benchmark")
def run_benchmark():
    """Runs automated security defense & hallucination benchmark."""
    return EvalEngine.benchmark_security_defenses()

# Mount Static UI
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    def serve_frontend():
        return FileResponse(os.path.join(static_dir, "index.html"))
