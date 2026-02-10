"""
Configuration management for Velociraptor Forensic MCP Server.

Loads settings from environment variables (or a .env file) and validates them
at startup. The config is split into three sections:

- VelociraptorConfig : connection to a remote Velociraptor instance
- ForensicConfig     : local forensic toolkit sandboxing
- ServerConfig       : MCP transport / logging / feature toggles
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class VelociraptorConfig:
    """Settings for the gRPC connection to a Velociraptor server."""

    api_key: str = ""
    ssl_verify: bool = True
    timeout: int = 30

    @classmethod
    def from_env(cls, prefix: str = "VELOCIRAPTOR") -> VelociraptorConfig:
        return cls(
            api_key=os.getenv(f"{prefix}_API_KEY", ""),
            ssl_verify=os.getenv(f"{prefix}_SSL_VERIFY", "true").lower() not in {"0", "false", "no"},
            timeout=int(os.getenv(f"{prefix}_TIMEOUT", "30")),
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def validate(self) -> None:
        if not self.api_key:
            return
        if self.api_key.endswith((".yaml", ".yml")) and not os.path.exists(self.api_key):
            raise ValueError(f"Velociraptor API config file not found: {self.api_key}")


@dataclass
class ForensicConfig:
    """Settings for the local forensic analysis tools."""

    safe_base: str = ""

    @classmethod
    def from_env(cls) -> ForensicConfig:
        return cls(safe_base=os.getenv("SAFE_BASE", ""))

    @property
    def is_configured(self) -> bool:
        return bool(self.safe_base)

    def validate(self) -> None:
        if self.safe_base and not os.path.isdir(self.safe_base):
            logger.warning("SAFE_BASE directory does not exist: %s", self.safe_base)


@dataclass
class ServerConfig:
    """Transport, logging and feature-toggle settings."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    disabled_tools: List[str] = field(default_factory=list)
    read_only: bool = False

    @classmethod
    def from_env(cls) -> ServerConfig:
        disabled: List[str] = []
        if raw := os.getenv("DISABLED_TOOLS"):
            disabled = [t.strip() for t in raw.split(",") if t.strip()]

        return cls(
            host=os.getenv("MCP_SERVER_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_SERVER_PORT", "8000")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            disabled_tools=disabled,
            read_only=os.getenv("READ_ONLY", "false").lower() in {"1", "true", "yes"},
        )


@dataclass
class Config:
    """Root configuration aggregating all sub-configs."""

    velociraptor: VelociraptorConfig
    forensic: ForensicConfig
    server: ServerConfig

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            velociraptor=VelociraptorConfig.from_env(),
            forensic=ForensicConfig.from_env(),
            server=ServerConfig.from_env(),
        )

    def validate(self) -> None:
        self.velociraptor.validate()
        self.forensic.validate()
        if not self.velociraptor.is_configured and not self.forensic.is_configured:
            logger.warning(
                "Neither Velociraptor nor local forensic toolkit is configured. "
                "Set VELOCIRAPTOR_API_KEY and/or SAFE_BASE to enable tools."
            )

    def setup_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, self.server.log_level.upper(), logging.INFO),
            format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        )
