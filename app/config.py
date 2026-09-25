import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    app_env: str = os.getenv("APP_ENV", "development")
    port: int = int(os.getenv("PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")

    llm_provider: str = os.getenv("LLM_PROVIDER", "mock")

    # Azure OpenAI
    azure_openai_api_key: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    azure_openai_endpoint: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    azure_openai_deployment_name: str = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4o-mini")
    azure_openai_api_version: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
    azure_openai_embedding_deployment: str = os.getenv("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "text-embedding-3-small")

    # Standard OpenAI
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # Google Gemini
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")

    # ChromaDB
    chroma_persist_dir: str = os.getenv("CHROMA_PERSIST_DIRECTORY", "./chroma_db")

settings = Settings()
