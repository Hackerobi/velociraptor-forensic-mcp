"""
Velociraptor gRPC client.

Handles authentication via api.config.yaml, running VQL queries, starting
collections, polling flow status, and retrieving results.

Adapted from socfortress/velociraptor-mcp-server with improvements for
async safety and structured error handling.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import grpc
import yaml
from pyvelociraptor import api_pb2, api_pb2_grpc

from .config import VelociraptorConfig
from .exceptions import VelociraptorAPIError, VelociraptorAuthenticationError

logger = logging.getLogger(__name__)


class VelociraptorClient:
    """Client for communicating with Velociraptor's gRPC API."""

    def __init__(self, config: VelociraptorConfig) -> None:
        self.config = config
        self.stub: Optional[api_pb2_grpc.APIStub] = None
        self._channel: Optional[grpc.Channel] = None

    async def authenticate(self) -> Dict[str, Any]:
        """Initialise the gRPC channel and test with ``SELECT * FROM info()``."""
        try:
            config_path = self.config.api_key
            if not config_path.endswith((".yaml", ".yml")):
                raise VelociraptorAuthenticationError(
                    "Please provide a path to api.config.yaml in VELOCIRAPTOR_API_KEY."
                )
            if not os.path.exists(config_path):
                raise VelociraptorAuthenticationError(f"Config file not found: {config_path}")

            with open(config_path, "r") as fh:
                api_config = yaml.safe_load(fh)

            for key in ("ca_certificate", "client_private_key", "client_cert", "api_connection_string"):
                if key not in api_config:
                    raise VelociraptorAuthenticationError(f"Missing field in config: {key}")

            creds = grpc.ssl_channel_credentials(
                root_certificates=api_config["ca_certificate"].encode(),
                private_key=api_config["client_private_key"].encode(),
                certificate_chain=api_config["client_cert"].encode(),
            )

            self._channel = grpc.secure_channel(
                api_config["api_connection_string"],
                creds,
                options=(("grpc.ssl_target_name_override", "VelociraptorServer"),),
            )
            self.stub = api_pb2_grpc.APIStub(self._channel)

            results = self._execute_vql("SELECT * FROM info()")
            return {
                "status": "authenticated",
                "server_url": api_config["api_connection_string"],
                "info": results,
            }
        except grpc.RpcError as exc:
            raise VelociraptorAuthenticationError(f"gRPC connection failed: {exc}") from exc
        except (VelociraptorAuthenticationError, VelociraptorAPIError):
            raise
        except Exception as exc:
            raise VelociraptorAuthenticationError(f"Authentication failed: {exc}") from exc

    async def ensure_connected(self) -> None:
        """Authenticate if not already connected."""
        if self.stub is None:
            await self.authenticate()

    def _execute_vql(self, vql: str) -> List[Dict[str, Any]]:
        if self.stub is None:
            raise RuntimeError("Not connected. Call authenticate() first.")

        request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
        results: List[Dict[str, Any]] = []

        for resp in self.stub.Query(request):
            if hasattr(resp, "error") and resp.error:
                raise VelociraptorAPIError(f"VQL error: {resp.error}")
            if hasattr(resp, "Response") and resp.Response:
                results.extend(json.loads(resp.Response))
        return results

    def run_vql(self, vql: str) -> List[Dict[str, Any]]:
        """Public wrapper — logs the query then delegates to ``_execute_vql``."""
        logger.info("VQL  ➤  %s", vql[:200])
        try:
            return self._execute_vql(vql)
        except grpc.RpcError as exc:
            raise VelociraptorAPIError(f"Query failed: {exc}") from exc

    def find_client(self, hostname: str) -> Optional[Dict[str, Any]]:
        vql = (
            "SELECT client_id, "
            "timestamp(epoch=first_seen_at) AS FirstSeen, "
            "timestamp(epoch=last_seen_at) AS LastSeen, "
            "os_info.hostname AS Hostname, "
            "os_info.fqdn AS Fqdn, "
            "os_info.system AS OSType, "
            "os_info.release AS OS, "
            "os_info.machine AS Machine, "
            "agent_information.version AS AgentVersion "
            f"FROM clients() "
            f"WHERE os_info.hostname =~ '^{hostname}$' OR os_info.fqdn =~ '^{hostname}$' "
            "ORDER BY LastSeen DESC LIMIT 1"
        )
        rows = self.run_vql(vql)
        return rows[0] if rows else None

    def start_collection(
        self, client_id: str, artifact: str, parameters: str = ""
    ) -> List[Dict[str, Any]]:
        vql = (
            f"LET collection <= collect_client("
            f"urgent='TRUE', client_id='{client_id}', "
            f"artifacts='{artifact}', env=dict({parameters})) "
            f"SELECT flow_id, request.artifacts AS artifacts, "
            f"request.specs[0] AS specs "
            f"FROM foreach(row=collection)"
        )
        return self.run_vql(vql)

    def get_flow_status(self, client_id: str, flow_id: str, artifact: str) -> str:
        vql = (
            f"SELECT * FROM flow_logs(client_id='{client_id}', flow_id='{flow_id}') "
            f"WHERE message =~ '^Collection {artifact} is done after' LIMIT 100"
        )
        try:
            return "FINISHED" if self.run_vql(vql) else "RUNNING"
        except Exception:
            return "ERROR"

    def get_flow_results(
        self, client_id: str, flow_id: str, artifact: str, fields: str = "*"
    ) -> List[Dict[str, Any]]:
        vql = (
            f"SELECT {fields} FROM source("
            f"client_id='{client_id}', flow_id='{flow_id}', artifact='{artifact}')"
        )
        return self.run_vql(vql)

    def close(self) -> None:
        if self._channel:
            self._channel.close()
            self._channel = None
            self.stub = None

    def __del__(self) -> None:
        self.close()
