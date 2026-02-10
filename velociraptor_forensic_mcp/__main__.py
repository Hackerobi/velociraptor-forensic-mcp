"""
CLI entry-point for the Velociraptor Forensic MCP Server.

Usage:
    # stdio transport (default — for Claude Desktop, MCP Inspector, etc.)
    velociraptor-forensic-mcp

    # SSE/HTTP transport for remote clients
    velociraptor-forensic-mcp --transport sse --host 0.0.0.0 --port 8000

    # Override log level
    velociraptor-forensic-mcp --log-level DEBUG
"""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="velociraptor-forensic-mcp",
        description="Unified MCP server: Velociraptor DFIR + Local Forensic Toolkit",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument("--host", default=None, help="Host for SSE transport (default: from env)")
    parser.add_argument("--port", type=int, default=None, help="Port for SSE transport (default: from env)")
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override LOG_LEVEL from .env",
    )
    args = parser.parse_args()

    # Late import so --help is fast
    from .config import Config
    from .server import create_server

    config = Config.from_env()
    if args.log_level:
        config.server.log_level = args.log_level

    server = create_server(config)

    if args.transport == "sse":
        server.run_sse(host=args.host, port=args.port)
    else:
        server.run()


if __name__ == "__main__":
    main()
