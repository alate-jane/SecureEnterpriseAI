import os
import uuid
from typing import Dict, List, Optional
import pypdf
import chromadb
from chromadb.config import Settings as ChromaSettings

from app.config import settings

class RAGEngine:
    """Document Ingestion, Vector Search, and Grounded Generation."""

    def __init__(self):
        # Initialize persistent ChromaDB vector store
        os.makedirs(settings.chroma_persist_dir, exist_ok=True)
        self.chroma_client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
        self.collection = self.chroma_client.get_or_create_collection(
            name="enterprise_knowledge",
            metadata={"hnsw:space": "cosine"}
        )

    def chunk_text(self, text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
        """Splits text into overlapping chunks for indexing."""
        words = text.split()
        chunks = []
        for i in range(0, len(words), chunk_size - overlap):
            chunk = " ".join(words[i:i + chunk_size])
            if chunk.strip():
                chunks.append(chunk)
        return chunks

    def ingest_pdf(self, file_path: str, classification: str = "internal") -> int:
        """Parses a PDF, chunks text, and stores vectors with security metadata."""
        reader = pypdf.PdfReader(file_path)
        filename = os.path.basename(file_path)
        all_chunks = []
        all_metadatas = []
        all_ids = []

        for page_num, page in enumerate(reader.pages):
            text = page.extract_text() or ""
            chunks = self.chunk_text(text)
            for chunk_idx, chunk in enumerate(chunks):
                chunk_id = f"{filename}_p{page_num + 1}_c{chunk_idx}_{uuid.uuid4().hex[:6]}"
                all_ids.append(chunk_id)
                all_chunks.append(chunk)
                all_metadatas.append({
                    "source": filename,
                    "page": page_num + 1,
                    "classification": classification,
                    "chunk_idx": chunk_idx
                })

        if all_chunks:
            self.collection.add(
                documents=all_chunks,
                metadatas=all_metadatas,
                ids=all_ids
            )

        return len(all_chunks)

    def ingest_raw_text(self, title: str, text: str, classification: str = "public") -> int:
        """Indexes raw text directly with classification."""
        chunks = self.chunk_text(text)
        ids = [f"{title}_c{i}_{uuid.uuid4().hex[:6]}" for i in range(len(chunks))]
        metadatas = [{
            "source": title,
            "page": 1,
            "classification": classification,
            "chunk_idx": i
        } for i in range(len(chunks))]

        if chunks:
            self.collection.add(
                documents=chunks,
                metadatas=metadatas,
                ids=ids
            )
        return len(chunks)

    def retrieve(self, query: str, rbac_filter: dict, top_k: int = 3) -> List[Dict]:
        """Queries the vector database applying RBAC clearance filters."""
        count = self.collection.count()
        if count == 0:
            return []

        results = self.collection.query(
            query_texts=[query],
            n_results=min(top_k, count),
            where=rbac_filter
        )

        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        retrieved = []
        for doc, meta, dist in zip(documents, metadatas, distances):
            retrieved.append({
                "content": doc,
                "metadata": meta,
                "score": round(1.0 - dist, 4) if dist is not None else 1.0
            })
        return retrieved

    def generate_grounded_response(self, query: str, context_chunks: List[Dict]) -> Dict:
        """
        Synthesizes an answer grounded strictly in retrieved context.
        Prevents hallucinations by refusing to guess unverified facts.
        """
        if not context_chunks:
            return {
                "answer": "No relevant documents found within your role clearance level to answer this enquiry.",
                "citations": [],
                "grounded": False
            }

        # Build context string
        context_str = "\n\n".join([
            f"[Source: {c['metadata']['source']} (Page {c['metadata'].get('page', 1)})]\n{c['content']}"
            for c in context_chunks
        ])

        system_prompt = (
            "You are an enterprise AI assistant for engineering and governance workflows. "
            "Your highest priority is accuracy and reliability. Answer the question STRICTLY using only the provided context. "
            "If the context does not contain enough information to answer definitively, state: "
            "'I cannot answer this enquiry from the provided enterprise documentation.' "
            "Never hallucinate or extrapolate beyond the text."
        )

        citations = [
            {
                "source": c["metadata"]["source"],
                "page": c["metadata"].get("page", 1),
                "classification": c["metadata"].get("classification", "unknown"),
                "relevance_score": c["score"]
            }
            for c in context_chunks
        ]

        if settings.llm_provider == "azure_openai" and settings.azure_openai_api_key:
            from openai import AzureOpenAI
            client = AzureOpenAI(
                azure_endpoint=settings.azure_openai_endpoint,
                api_key=settings.azure_openai_api_key,
                api_version=settings.azure_openai_api_version
            )
            response = client.chat.completions.create(
                model=settings.azure_openai_deployment_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Context:\n{context_str}\n\nQuestion: {query}"}
                ],
                temperature=0.0
            )
            answer_text = response.choices[0].message.content
        elif settings.llm_provider == "openai" and settings.openai_api_key:
            from openai import OpenAI
            client = OpenAI(api_key=settings.openai_api_key)
            response = client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Context:\n{context_str}\n\nQuestion: {query}"}
                ],
                temperature=0.0
            )
            answer_text = response.choices[0].message.content
        else:
            # Deterministic mock generation for zero-cost offline demonstration
            answer_text = (
                f"Based on verified enterprise documentation ({citations[0]['source']}):\n"
                f"{context_chunks[0]['content'][:250]}..."
            )

        return {
            "answer": answer_text,
            "citations": citations,
            "grounded": True
        }
