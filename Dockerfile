# Runs the leakferret MCP server in a container, for hosts that launch MCP
# servers over Docker (e.g. Glama). The server speaks JSON-RPC over stdio.
#
#   docker build -t leakferret-mcp .
#   docker run --rm -i leakferret-mcp
#
# Installing @leakferret/mcp pulls @leakferret/cli, whose postinstall downloads
# the pinned, checksum-verified native binary for the platform.
FROM node:20-slim

# ca-certificates for the binary download; git lets the `leakferret org`
# subcommand clone repositories (harmless for the MCP server itself).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @leakferret/mcp@latest

# stdio MCP server: reads JSON-RPC requests on stdin, writes responses to stdout.
ENTRYPOINT ["leakferret-mcp"]
