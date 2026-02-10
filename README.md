# 🦖 Velociraptor Forensic MCP Server

**Turn Claude Desktop into a DFIR workstation.**

A unified Model Context Protocol (MCP) server that connects Claude Desktop to your Velociraptor instance AND local forensic tools. Remote endpoint investigation + local evidence analysis in one server. Docker deployment for Velociraptor included.

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![Docker](https://img.shields.io/badge/Docker-Ready-blue) ![Velociraptor](https://img.shields.io/badge/Velociraptor-0.75+-green) ![Tools](https://img.shields.io/badge/DFIR_Tools-12-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What This Does

Instead of switching between the Velociraptor GUI, terminal VQL sessions, and forensic scripts, you talk to Claude and it runs them for you. Ask Claude to:

- *"Look up workstation-01 and tell me when it was last seen"* → Queries Velociraptor for client info
- *"Collect the user list from that endpoint"* → Starts a `Linux.Sys.Users` artifact collection and retrieves results
- *"Hash all files in /evidence/malware-samples/"* → Recursively SHA-256 hashes a local directory
- *"Check syslog for any mentions of that binary"* → Scans system logs with keyword search
- *"Cross-reference the file metadata with log entries"* → Correlates timestamps, hashes, and log hits into a forensic report
- *"Run a VQL query to show all running processes on the endpoint"* → Executes custom VQL directly

All results come back in the chat. No copy-pasting. No tab switching. Full forensic chain from endpoint to evidence.

---

## 🛠️ Integrated Tools (12)

### Remote — Velociraptor (vr_*)
| Tool | Description |
|------|-------------|
| **vr_authenticate** | Test gRPC connection to Velociraptor |
| **vr_get_agent_info** | Look up a client by hostname → client_id, OS, agent version, last seen |
| **vr_run_vql** | Execute arbitrary VQL queries on the server |
| **vr_list_artifacts** | List all available client artifacts with descriptions |
| **vr_artifact_details** | Get full specs for a specific artifact |
| **vr_collect_artifact** | Start artifact collection on a remote endpoint (returns flow_id) |
| **vr_get_collection_results** | Poll and retrieve completed collection results (with retry logic) |

### Local Forensic (local_*)
| Tool | Description |
|------|-------------|
| **local_file_metadata** | SHA-256, size, timestamps for a file (sandboxed to SAFE_BASE) |
| **local_hash_directory** | Recursively hash every file in a directory |
| **local_scan_syslog** | Search Linux syslog or macOS unified log by keyword |
| **local_correlate** | Cross-reference file metadata with log entries |
| **local_forensic_report** | Generate structured forensic report combining file + log data |

### Key Features
- **Dual-mode**: Either toolkit works independently — deploy with just Velociraptor, just local tools, or both
- **Path sandboxing**: All local_* tools validate paths stay within SAFE_BASE
- **Async flow polling**: Collection results auto-retry until the flow completes
- **Multi-source artifacts**: Handles artifacts with multiple data sources automatically
- **Tool filtering**: Disable individual tools via DISABLED_TOOLS env var
- **Read-only mode**: Block write operations (artifact collection) with READ_ONLY=true

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Claude Desktop

### 1. Deploy Velociraptor (Docker)

```bash
cd docker/
docker compose up -d

# Wait ~30 seconds for initialization
docker logs velociraptor --tail 10
# Should see: "Starting gRPC API server" and "Frontend is ready"
```

Default GUI: https://localhost:9889 (admin/admin — change this!)

### 2. Generate API Key

```bash
chmod +x generate-api-key.sh
./generate-api-key.sh
```

This creates `api.config.yaml` with the gRPC credentials and automatically fixes the connection string for host access.

### 3. Install the MCP Server

```bash
cd ../
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### 4. Configure

```bash
cp .env.example .env
# Edit .env — set your paths:
#   VELOCIRAPTOR_API_KEY=/path/to/api.config.yaml
#   SAFE_BASE=/home/youruser/evidence
```

### 5. Configure Claude Desktop

Add to `~/.config/Claude/claude_desktop_config.json` (Linux) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "velociraptor-forensic": {
      "command": "/path/to/velociraptor-forensic-mcp/.venv/bin/python",
      "args": ["-m", "velociraptor_forensic_mcp"],
      "cwd": "/path/to/velociraptor-forensic-mcp",
      "env": {
        "VELOCIRAPTOR_API_KEY": "/path/to/api.config.yaml",
        "VELOCIRAPTOR_SSL_VERIFY": "false",
        "SAFE_BASE": "/home/youruser/evidence",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### 6. Restart Claude Desktop

The tools will appear automatically. Start investigating.

---

## 🔑 Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `VELOCIRAPTOR_API_KEY` | Path to api.config.yaml | — | For remote tools |
| `VELOCIRAPTOR_SSL_VERIFY` | Verify gRPC TLS certs | `true` | |
| `VELOCIRAPTOR_TIMEOUT` | gRPC timeout (seconds) | `30` | |
| `SAFE_BASE` | Root directory for local forensic tools | — | For local tools |
| `MCP_SERVER_HOST` | Bind host for SSE transport | `127.0.0.1` | |
| `MCP_SERVER_PORT` | Bind port for SSE transport | `8000` | |
| `LOG_LEVEL` | DEBUG/INFO/WARNING/ERROR | `INFO` | |
| `DISABLED_TOOLS` | Comma-separated tool names to disable | — | |
| `READ_ONLY` | Block artifact collection | `false` | |

---

## 🐳 Docker Velociraptor Setup

The `docker/` folder contains everything to run Velociraptor in Docker with ports mapped to avoid common conflicts:

| Host Port | Service | Purpose |
|-----------|---------|--------|
| 9000 | Client frontend | Velociraptor agent check-in |
| 9001 | gRPC API | MCP server connects here |
| 9889 | Web GUI | Your browser |

### Enrolling a Test Client

To enroll the machine running Docker as a Velociraptor client:

```bash
cd docker/

# Copy client binary and config
docker cp velociraptor:/velociraptor/clients/linux/velociraptor_client_repacked ./velociraptor_client
chmod +x velociraptor_client

docker exec velociraptor cat client.config.yaml > client.config.yaml
sed -i 's|https://VelociraptorServer:8000/|https://localhost:9000/|' client.config.yaml

# Run the client (Ctrl+C to stop)
sudo ./velociraptor_client --config client.config.yaml client -v
```

---

## 💡 Usage Examples

### Full Endpoint Investigation
> "Look up the endpoint pop-os, collect its user list, and check syslog for any suspicious entries"

Claude chains: `vr_get_agent_info` → `vr_collect_artifact` → `vr_get_collection_results` → `local_scan_syslog`

### File Integrity Check
> "Hash all files in /evidence/case-2024/ and check if any appear in the system logs"

Claude chains: `local_hash_directory` → `local_correlate` for each suspicious file

### Custom VQL Investigation
> "Run a VQL query to show me all listening network connections on client C.1393a876d1c48287"

Claude uses `vr_collect_artifact` with `Linux.Network.Netstat` or writes custom VQL via `vr_run_vql`

### Quick Triage
> "Scan syslog for 'authentication failure' and give me a summary"

Claude uses `local_scan_syslog` and synthesizes the results

---

## 📁 Project Structure

```
velociraptor-forensic-mcp/
├── velociraptor_forensic_mcp/
│   ├── __init__.py            # Package metadata
│   ├── __main__.py            # CLI entry point
│   ├── config.py              # Dataclass configs (Velociraptor, Forensic, Server)
│   ├── exceptions.py          # Custom exception hierarchy
│   ├── vr_client.py           # Velociraptor gRPC client
│   ├── forensic_helpers.py    # Local forensic functions
│   └── server.py              # FastMCP server with all tools/prompts/resources
├── docker/
│   ├── docker-compose.yaml    # Velociraptor Docker deployment
│   └── generate-api-key.sh    # API key generation script
├── tests/
│   └── test_forensic.py       # Unit tests
├── pyproject.toml             # Python packaging
├── .env.example               # Configuration template
└── README.md
```

---

## 🔒 Security

- **API key protection**: `api.config.yaml` contains a private key — `chmod 600` it
- **Path sandboxing**: All local tools are restricted to the SAFE_BASE directory
- **Least privilege**: Generate API keys with `--role api,investigator` not `administrator`
- **Tool filtering**: Disable tools you don't need via DISABLED_TOOLS
- **Read-only mode**: Set `READ_ONLY=true` to prevent artifact collection
- **Never commit** `api.config.yaml` or `.env` to version control

---

## 🧪 Running Tests

```bash
source .venv/bin/activate
pytest -v
```

---

## 🏗️ Architecture

This server combines two open-source projects into a unified MCP interface:

- **Remote tools** adapted from [socfortress/velociraptor-mcp-server](https://github.com/socfortress/velociraptor-mcp-server) (gRPC operations)
- **Local tools** adapted from [axdithyaxo/mcp-forensic-toolkit](https://github.com/axdithyaxo/mcp-forensic-toolkit) (sandboxed file analysis)

Both toolkits activate independently based on which environment variables are set. You can run Velociraptor-only, local-only, or both together.

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized digital forensics and incident response only**. Always ensure you have proper authorization before collecting artifacts from endpoints. Unauthorized access to computer systems is illegal.

---

## 🤝 Contributing

Pull requests welcome. To add a new tool:

1. Add the function in `forensic_helpers.py` (local) or `vr_client.py` (remote)
2. Create a Pydantic input model in `server.py`
3. Register the tool in `_register_forensic_tools()` or `_register_velociraptor_tools()`
4. Add tests
5. Submit a PR

---

## 📬 Contact

- **Discord:** sgtwolf787
- **GitHub:** [@Hackerobi](https://github.com/Hackerobi)

White hat or no hat 🎩

---

*Built with Claude. Tested on live Velociraptor deployment. Stay legal.*
