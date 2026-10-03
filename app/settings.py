from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AICL_", env_file=".env", extra="ignore")
    demo_mode: bool = True
    policy_path: Path = ROOT / "config/policy.yaml"
    auth_file: Path | None = None
    admin_token: str = "demo-admin-token"
    opa_url: str = "http://127.0.0.1:8181"
    opa_binary: Path | None = None
    redis_url: str | None = None
    database_url: str | None = None
    llm_url: str = "http://127.0.0.1:8081"
    mcp_url: str = "http://127.0.0.1:8082"
    mcp_output_trust: Literal["trusted", "untrusted"] | None = None
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:4b"
    semantic_provider: Literal["none", "prompt_guard", "deberta", "ollama"] = "none"
    prompt_guard_path: str = str(ROOT / "models/prompt-guard")
    deberta_path: str = str(ROOT / "models/deberta")
    alignment_provider: Literal["none", "ollama"] = "none"
    jwt_jwks_path: Path | None = None
    jwt_issuer: str = "http://aicl.local/issuer"
    jwt_audience: str = "ai-control-layer"
    semantic_timeout: float = Field(default=5, gt=0, le=60)
    upstream_timeout: float = Field(default=15, gt=0, le=120)
    otlp_endpoint: str | None = None
    max_body_bytes: int = 262144

    @model_validator(mode="after")
    def deployment_auth(self):
        if not self.demo_mode:
            if not self.auth_file or self.admin_token == "demo-admin-token" or len(self.admin_token) < 24:
                raise ValueError(
                    "Deployment mode requires AUTH_FILE and a distinct ADMIN_TOKEN >=24 characters"
                )
            if not self.redis_url or not self.database_url:
                raise ValueError("Deployment mode requires shared Redis and PostgreSQL stores")
        return self
