import os
import sys

# Ensure root directory is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.rag_engine import RAGEngine

def seed():
    engine = RAGEngine()
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "data", "sample_docs")

    docs = [
        ("substation_safety_guidelines.txt", "internal"),
        ("environmental_water_quality_policy.txt", "public"),
        ("executive_capital_works_strategy_2026.txt", "confidential")
    ]

    print("=== Seeding Enterprise Knowledge Base ===")
    for filename, classification in docs:
        file_path = os.path.join(sample_dir, filename)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            chunks = engine.ingest_raw_text(filename, content, classification=classification)
            print(f"✓ Indexed '{filename}' [{classification.upper()}]: {chunks} chunks")

    print(f"\nTotal Vectors in ChromaDB: {engine.collection.count()}")

if __name__ == "__main__":
    seed()
