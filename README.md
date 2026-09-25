# Secure Enterprise AI Assistant 🛡️🤖

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Azure OpenAI](https://img.shields.io/badge/Azure_OpenAI-Ready-0078D4.svg)](https://azure.microsoft.com/)
[![ChromaDB](https://img.shields.io/badge/Vector_DB-ChromaDB-purple.svg)](https://www.trychroma.com/)
[![Security Evaluated](https://img.shields.io/badge/Security-RBAC_%26_Evals-emerald.svg)]()

> **Production-grade Retrieval-Augmented Generation (RAG) and Governance Pipeline for Engineering and Infrastructure Consultancies.** Built to satisfy enterprise data privacy, access control, and anti-hallucination compliance.

---

## 🎯 Architecture & Pipeline

```
                                [Enterprise Web UI]
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            FastAPI Backend Layer                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Security Engine                                                         │
│     ├── Adversarial Prompt Injection Defense (heuristic + regex inspection) │
│     ├── Australian PII Redaction (phones, emails, identifiers masked)       │
│     └── Role-Based Access Control (RBAC) (public / internal / confidential) │
├─────────────────────────────────────────────────────────────────────────────┤
│  2. RAG & Vector Engine                                                     │
│     ├── Document Ingestion (PDFs, Markdown, Technical Manuals via PyPDF)    │
│     ├── Vector Store (Persistent ChromaDB cosine embeddings)                │
│     └── Grounded Context Assembly (Strict anti-hallucination prompting)    │
├─────────────────────────────────────────────────────────────────────────────┤
│  3. LLMOps & Evaluation Suite                                               │
│     ├── Automated Faithfulness / Groundedness Token Scoring                 │
│     ├── Automated Security Defense Benchmarking                             │
│     └── Response Latency & Token Budget Tracking                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

* **🛡️ Pre-Flight Security Gate:** Automatically intercepts adversarial prompts (jailbreaks, prompt leaking, instruction overrides) before execution, conserving model token budget and protecting system integrity.
* **🔒 Australian PII Anonymization:** Scrubs mobile numbers (`+61 / 04xx`), emails, and credit card numbers from user queries before transmission to external model endpoints.
* **🏷️ Role-Based Access Control (RBAC):** Restricts document retrieval according to user clearance (`guest`, `employee`, `executive`). Confidential financial or strategic reports are invisible to unprivileged queries.
* **📊 Automated LLMOps Evals:** Measures answer faithfulness against retrieved source chunks to actively detect and prevent hallucinations.
* **⚡ Multi-Provider Support:** Switch between **Azure OpenAI**, standard **OpenAI**, or deterministic **Mock** mode for offline local demonstrations.

---

## 🚀 Quickstart Guide

### 1. Prerequisites
* Python 3.10 or higher
* Git

### 2. Installation
```powershell
# Clone the repository
git clone https://github.com/alate-jane/SecureEnterpriseAI.git
cd SecureEnterpriseAI

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Seed Demo Enterprise Knowledge
Populate the local ChromaDB vector store with sample engineering safety manuals, environmental guidelines, and strategic briefings:
```powershell
python scripts/seed_demo_data.py
```

### 4. Launch Application
```powershell
uvicorn app.main:app --reload --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser to interact with the dashboard.

---

## 🧪 Running Automated Tests
```powershell
pytest -v
```
Verifies injection protection, PII masking, RBAC clearance enforcement, and faithfulness scoring.

---

## 📄 License
MIT License. Developed for enterprise evaluation and demonstration.
