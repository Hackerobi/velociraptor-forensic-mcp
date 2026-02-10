#!/bin/bash
# generate-api-key.sh
# Run AFTER Velociraptor is up and healthy.

set -e

CONTAINER="velociraptor"
API_USER="mcp-forensic-agent"
API_ROLE="api,investigator"
OUTPUT_FILE="./api.config.yaml"

echo "==> Generating API key inside the Velociraptor container..."

# Generate inside the container (requires positional output arg)
docker exec -i "$CONTAINER" \
  ./velociraptor --config server.config.yaml \
    config api_client \
    --name "$API_USER" \
    --role "$API_ROLE" \
    /velociraptor/api.config.yaml

# Copy it out to the host
docker cp "$CONTAINER":/velociraptor/api.config.yaml "$OUTPUT_FILE"

# Fix connection string: container uses internal hostname,
# but MCP server runs on the host via published port 9001
sed -i 's/VelociraptorServer:8001/localhost:9001/' "$OUTPUT_FILE"
sed -i 's/0.0.0.0:8001/localhost:9001/' "$OUTPUT_FILE"

chmod 600 "$OUTPUT_FILE"

echo ""
echo "==> Done!  API config written to: $OUTPUT_FILE"
echo ""
echo "    User:   $API_USER"
echo "    Roles:  $API_ROLE"
echo "    API:    localhost:9001"
echo ""
echo "Next steps:"
echo "  cp $OUTPUT_FILE ../"
echo "  cd .."
echo "  # Then update .env with: VELOCIRAPTOR_API_KEY=./api.config.yaml"
