import os
import time
import shutil
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.config import settings
from app.core.security import SecurityEngine
from app.core.rag_engine import RAGEngine
from app.core.eval_engine import EvalEngine

app = FastAPI(
    title="Secure Enterprise AI Assistant",
    description="Production-grade RAG and Governance Pipeline for Engineering and Enterprise Workflows",
    version="1.0.0"
)

# Initialize engines
rag = RAGEngine()

class QueryRequest(BaseModel):
    query: str
    user_role: str = "employee"

class QueryResponse(BaseModel):
    answer: str
    citations: List[dict]
    grounded: bool
    faithfulness_score: float
    security_audit: dict
    latency_ms: float

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "provider": settings.llm_provider,
        "indexed_documents_count": rag.collection.count()
    }

@app.post("/api/query", response_model=QueryResponse)
def handle_query(req: QueryRequest):
    start_time = time.time()

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
    rbac_filter = SecurityEngine.build_rbac_filter(req.user_role)

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
            "role_used": req.user_role,
            "allowed_classifications": SecurityEngine.get_allowed_classifications(req.user_role)
        },
        latency_ms=latency
    )

@app.post("/api/upload")
async def upload_document(
    file: UploadFile = File(...),
    classification: str = Form("internal")
):
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
