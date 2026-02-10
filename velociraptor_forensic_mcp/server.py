"""
Unified MCP server: Velociraptor DFIR + Local Forensic Toolkit.

Registers tools from two domains:

  vr_*     — Remote Velociraptor operations (gRPC)
  local_*  — Sandboxed local forensic analysis

Either (or both) can be enabled depending on which environment variables
are configured. Tools can be individually disabled via DISABLED_TOOLS.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from .config import Config
from .exceptions import SafePathError
from .forensic_helpers import (
    correlate_file_and_logs,
    generate_forensic_report,
    get_file_metadata,
    hash_directory,
    scan_syslog,
)
from .vr_client import VelociraptorClient

logger = logging.getLogger(__name__)

MAX_TEXT = 32_000


def _truncate(text: str, limit: int = MAX_TEXT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[…truncated {len(text) - limit} chars…]"


def _json(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str)


# Pydantic input models

class EmptyArgs(BaseModel):
    pass

class HostnameArgs(BaseModel):
    hostname: str = Field(..., description="Hostname or FQDN of the Velociraptor client")

class VQLArgs(BaseModel):
    vql: str = Field(..., description="VQL query to execute on the Velociraptor server")
    max_rows: Optional[int] = Field(None, description="Maximum rows to return")
    timeout: Optional[int] = Field(None, description="Query timeout in seconds")

class CollectArtifactArgs(BaseModel):
    client_id: str = Field(..., description="Velociraptor client ID (e.g. C.abc123)")
    artifact: str = Field(..., description="Artifact name (e.g. Windows.System.Users)")
    parameters: str = Field("", description="Comma-separated key='value' pairs for the artifact")

class GetResultsArgs(BaseModel):
    client_id: str = Field(..., description="Velociraptor client ID")
    flow_id: str = Field(..., description="Flow ID from a previous collection")
    artifact: str = Field(..., description="Artifact name that was collected")
    fields: str = Field("*", description="Comma-separated field list or '*'")
    max_retries: int = Field(5, description="Retry count while waiting for flow completion", ge=1, le=30)
    retry_delay: int = Field(5, description="Seconds between retries", ge=1, le=60)

class ArtifactNameArgs(BaseModel):
    artifact_name: str = Field(..., description="Fully-qualified artifact name (e.g. Windows.System.Users)")

class FilePathArgs(BaseModel):
    path: str = Field(..., description="Absolute path to the target file")

class DirPathArgs(BaseModel):
    path: str = Field(..., description="Absolute path to the directory to hash")

class SyslogArgs(BaseModel):
    keyword: str = Field(..., description="Case-insensitive keyword to search in system logs")
    max_lines: int = Field(100, description="Maximum log lines to return", ge=1, le=500)

class CorrelateArgs(BaseModel):
    filename: str = Field(..., description="Absolute path to the file to correlate")
    keyword: str = Field("modified", description="Keyword to search in system logs")


class ForensicMCPServer:
    """Builds and holds the FastMCP application with all registered tools."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._vr_client: Optional[VelociraptorClient] = None
        self.mcp = FastMCP("velociraptor_forensic_mcp")

        if config.velociraptor.is_configured:
            self._register_velociraptor_tools()
            logger.info("Velociraptor tools registered (remote).")
        else:
            logger.info("Velociraptor not configured — remote tools skipped.")

        if config.forensic.is_configured:
            self._register_forensic_tools()
            logger.info("Local forensic tools registered (SAFE_BASE=%s).", config.forensic.safe_base)
        else:
            logger.info("SAFE_BASE not configured — local forensic tools skipped.")

    def _enabled(self, name: str) -> bool:
        return name not in self.config.server.disabled_tools

    def _vr(self) -> VelociraptorClient:
        if self._vr_client is None:
            self._vr_client = VelociraptorClient(self.config.velociraptor)
        return self._vr_client

    def _register_velociraptor_tools(self) -> None:

        if self._enabled("vr_authenticate"):
            @self.mcp.tool(name="vr_authenticate", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
            async def vr_authenticate(args: EmptyArgs) -> str:
                """Initialise and test the gRPC connection to Velociraptor."""
                try:
                    result = await self._vr().authenticate()
                    return f"Authentication successful:\n{_json(result)}"
                except Exception as exc:
                    return f"Authentication failed: {exc}"

        if self._enabled("vr_get_agent_info"):
            @self.mcp.tool(name="vr_get_agent_info", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
            async def vr_get_agent_info(args: HostnameArgs) -> str:
                """Look up a Velociraptor client by hostname/FQDN."""
                try:
                    client = self._vr()
                    await client.ensure_connected()
                    info = client.find_client(args.hostname)
                    if info is None:
                        return f"No client found for hostname: {args.hostname}"
                    return _json(info)
                except Exception as exc:
                    return f"Error: {exc}"

        if self._enabled("vr_run_vql"):
            @self.mcp.tool(name="vr_run_vql", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
            async def vr_run_vql(args: VQLArgs) -> str:
                """Execute an arbitrary VQL query on the Velociraptor server."""
                try:
                    client = self._vr()
                    await client.ensure_connected()
                    rows = client.run_vql(args.vql)
                    return _truncate(_json(rows))
                except Exception as exc:
                    return f"VQL error: {exc}"

        if self._enabled("vr_list_artifacts"):
            @self.mcp.tool(name="vr_list_artifacts", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
            async def vr_list_artifacts(args: EmptyArgs) -> str:
                """List all client artifacts with short descriptions."""
                try:
                    client = self._vr()
                    await client.ensure_connected()
                    vql = ("LET params(data) = SELECT name FROM data "
                           "SELECT name, description, params(data=parameters) AS parameters "
                           "FROM artifact_definitions() WHERE type =~ 'client'")
                    rows = client.run_vql(vql)
                    summaries = [{"name": r["name"], "description": (r.get("description") or "")[:120], "parameters": [p["name"] for p in r.get("parameters", [])]} for r in rows]
                    return _truncate(_json(summaries))
                except Exception as exc:
                    return f"Error: {exc}"

        if self._enabled("vr_artifact_details"):
            @self.mcp.tool(name="vr_artifact_details", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
            async def vr_artifact_details(args: ArtifactNameArgs) -> str:
                """Get full details for a Velociraptor artifact."""
                try:
                    client = self._vr()
                    await client.ensure_connected()
                    vql = (f"SELECT name, description, parameters, sources.name AS source_names "
                           f"FROM artifact_definitions() WHERE name = '{args.artifact_name}'")
                    rows = client.run_vql(vql)
                    if not rows:
                        return f"No artifact found: {args.artifact_name}"
                    return _truncate(_json(rows[0]))
                except Exception as exc:
                    return f"Error: {exc}"

        if self._enabled("vr_collect_artifact") and not self.config.server.read_only:
            @self.mcp.tool(name="vr_collect_artifact", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
            async def vr_collect_artifact(args: CollectArtifactArgs) -> str:
                """Start an artifact collection on a remote client."""
                try:
                    client = self._vr()
                    await client.ensure_connected()
                    resp = client.start_collection(args.client_id, args.artifact, args.parameters)
                    if not resp or "flow_id" not in resp[0]:
                        return f"Failed to start collection: {_json(resp)}"
                    return f"Collection started:\n{_json(resp[0])}"
                except Exception as exc:
                    return f"Error: {exc}"

        if self._enabled("vr_get_collection_results"):
            @self.mcp.tool(name="vr_get_collection_results", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
            async def vr_get_collection_results(args: GetResultsArgs) -> str:
                """Retrieve results from a completed collection flow."""
                try:
                    client = self._vr()
                    await client.ensure_connected()
                    detail_vql = (f"SELECT sources.name AS source_names FROM artifact_definitions() WHERE name = '{args.artifact}'")
                    details = client.run_vql(detail_vql)
                    source_names = []
                    if details:
                        source_names = [s for s in (details[0].get("source_names") or []) if s and s.strip()]
                    artifacts_to_check = [f"{args.artifact}/{s}" for s in source_names] if source_names else [args.artifact]
                    all_results: dict = {}
                    pending = []
                    for attempt in range(args.max_retries):
                        pending = []
                        for art in artifacts_to_check:
                            if art in all_results:
                                continue
                            status = client.get_flow_status(args.client_id, args.flow_id, art)
                            if status == "FINISHED":
                                all_results[art] = client.get_flow_results(args.client_id, args.flow_id, art, args.fields)
                            else:
                                pending.append(art)
                        if not pending:
                            break
                        if attempt < args.max_retries - 1:
                            await asyncio.sleep(args.retry_delay)
                    if not all_results:
                        return f"No results after {args.max_retries} retries for flow {args.flow_id}. Checked: {artifacts_to_check}"
                    combined = {"flow_id": args.flow_id, "artifact": args.artifact, "sources": all_results, "total_records": sum(len(v) for v in all_results.values()), "completed": len(all_results), "total_sources": len(artifacts_to_check)}
                    if pending:
                        combined["incomplete_sources"] = pending
                    return _truncate(_json(combined))
                except Exception as exc:
                    return f"Error: {exc}"

    def _register_forensic_tools(self) -> None:
        safe_base = self.config.forensic.safe_base

        if self._enabled("local_file_metadata"):
            @self.mcp.tool(name="local_file_metadata", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
            async def local_file_metadata(args: FilePathArgs) -> str:
                """Return size, timestamps, and SHA-256 hash for a file within SAFE_BASE."""
                try:
                    meta = get_file_metadata(args.path, safe_base)
                    return _json(meta)
                except (SafePathError, OSError) as exc:
                    return f"Error: {exc}"

        if self._enabled("local_hash_directory"):
            @self.mcp.tool(name="local_hash_directory", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
            async def local_hash_directory(args: DirPathArgs) -> str:
                """Recursively SHA-256 hash every file under a directory."""
                try:
                    results = hash_directory(args.path, safe_base)
                    return _truncate(_json(results))
                except (SafePathError, OSError) as exc:
                    return f"Error: {exc}"

        if self._enabled("local_scan_syslog"):
            @self.mcp.tool(name="local_scan_syslog", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
            async def local_scan_syslog(args: SyslogArgs) -> str:
                """Search system logs for a keyword."""
                hits = scan_syslog(args.keyword, args.max_lines)
                return _truncate(_json(hits))

        if self._enabled("local_correlate"):
            @self.mcp.tool(name="local_correlate", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
            async def local_correlate(args: CorrelateArgs) -> str:
                """Cross-reference a file's metadata with system log entries."""
                result = correlate_file_and_logs(args.filename, args.keyword, safe_base)
                return _json(result)

        if self._enabled("local_forensic_report"):
            @self.mcp.tool(name="local_forensic_report", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
            async def local_forensic_report(args: CorrelateArgs) -> str:
                """Generate a structured forensic report."""
                report = generate_forensic_report(args.filename, args.keyword, safe_base)
                return _json(report)

        @self.mcp.prompt("investigate-file")
        def investigate_file_prompt(filename: str) -> str:
            return (f"You are a digital forensic analyst. Use `local_file_metadata` on '{filename}' "
                    "to retrieve size, timestamps, and SHA-256 hash. Assess if there are signs of "
                    "tampering or suspicious timing. If a Velociraptor server is connected, consider "
                    "using `vr_run_vql` to check for related endpoint activity.")

        @self.mcp.prompt("triage-system-logs")
        def triage_logs_prompt(keyword: str = "error") -> str:
            return (f"Search system logs for '{keyword}' using `local_scan_syslog`. "
                    "Summarize the most relevant entries indicating errors, warnings, or "
                    "security events. Recommend whether immediate action is needed.")

        @self.mcp.prompt("full-endpoint-investigation")
        def full_investigation_prompt(hostname: str, filename: str) -> str:
            return (f"Conduct a full DFIR investigation:\n"
                    f"1. Use `vr_get_agent_info` to look up endpoint '{hostname}'.\n"
                    f"2. Use `local_file_metadata` on '{filename}' for integrity data.\n"
                    f"3. Use `local_correlate` to cross-reference logs.\n"
                    f"4. Use `vr_run_vql` to check recent process execution or network connections.\n"
                    f"5. Summarize findings in a forensic timeline.")

        @self.mcp.resource("toolkit://about")
        def about() -> str:
            vr_status = "connected" if self.config.velociraptor.is_configured else "not configured"
            local_status = self.config.forensic.safe_base or "not configured"
            return ("🔍 Velociraptor Forensic MCP Server\n\n"
                    f"Velociraptor: {vr_status}\n"
                    f"Local forensic SAFE_BASE: {local_status}\n\n"
                    "Remote tools (vr_*): endpoint queries, artifact collection, VQL\n"
                    "Local tools (local_*): file metadata, hashing, syslog, correlation reports")

    def run(self) -> None:
        self.mcp.run()

    def run_sse(self, host: str | None = None, port: int | None = None) -> None:
        import uvicorn
        host = host or self.config.server.host
        port = port or self.config.server.port
        logger.info("Starting SSE transport on %s:%d", host, port)
        uvicorn.run(self.mcp.sse_app, host=host, port=port)

    async def close(self) -> None:
        if self._vr_client:
            self._vr_client.close()


def create_server(config: Config | None = None) -> ForensicMCPServer:
    if config is None:
        config = Config.from_env()
    config.validate()
    config.setup_logging()
    return ForensicMCPServer(config)
