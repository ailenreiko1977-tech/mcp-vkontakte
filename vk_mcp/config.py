from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    public_url: str
    issuer: str
    encryption_key: str
    cookie_secret: str
    oidc_client_id: str
    oidc_client_secret: str
    db_path: Path = Path(".local/vk.sqlite3")
    scope: str = "vk-mcp"
    vk_app_id: int = 0

    def __post_init__(self):
        for url in (self.public_url, self.issuer):
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment or parsed.username:
                raise ValueError("Public and issuer URLs must be HTTPS without credentials, query or fragment")
        if urlsplit(self.public_url).path not in ("", "/"):
            raise ValueError("PUBLIC_URL must be a site origin")
        if len(self.cookie_secret) < 32:
            raise ValueError("COOKIE_SECRET must contain at least 32 characters")
        if not isinstance(self.vk_app_id,int) or self.vk_app_id<0:
            raise ValueError("VK_MINI_APP_ID must be a nonnegative integer")

    @property
    def resource(self):
        return self.public_url.rstrip("/") + "/mcp"

    @classmethod
    def from_env(cls):
        required = ["PUBLIC_URL", "OIDC_ISSUER", "ENCRYPTION_KEY", "COOKIE_SECRET", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"]
        if any(not os.getenv(name) for name in required):
            raise ValueError("Missing server configuration; follow docs/DEPLOYMENT.md")
        return cls(*(os.environ[name].rstrip("/") if name in ("PUBLIC_URL", "OIDC_ISSUER") else os.environ[name] for name in required),
                   db_path=Path(os.getenv("DB_PATH", ".local/vk.sqlite3")),
                   vk_app_id=int(os.getenv("VK_MINI_APP_ID","0")))
