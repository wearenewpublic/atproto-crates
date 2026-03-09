# atpmcp

A local MCP (Model Context Protocol) server for AT Protocol DAG-CBOR CID generation.

## Overview

A standalone MCP server binary that communicates over stdio using JSON-RPC 2.0. It provides a `create_record_cid` tool that accepts a JSON object, serializes it to DAG-CBOR, hashes it with SHA-256, and returns the CIDv1 string. This allows AI assistants like Claude to compute content identifiers for AT Protocol records directly.

## Tools

- **`create_record_cid`**: Accepts a JSON record object and returns its DAG-CBOR CID. The record is serialized using deterministic DAG-CBOR encoding, hashed with SHA-256, and returned as a CIDv1 base32 string.

## Building

```bash
cargo build -p atpmcp
```

## Claude Code Integration

Add the following to your Claude Code MCP configuration (`~/.claude/claude_code_config.json`):

```json
{
  "mcpServers": {
    "atpmcp": {
      "command": "/path/to/atpmcp"
    }
  }
}
```

Replace `/path/to/atpmcp` with the absolute path to the compiled binary (e.g., `target/release/atpmcp` after running `cargo build -p atpmcp --release`).

Or, if `atpmcp` is already in your PATH:

```bash
tmp=$(jq '.mcpServers.atpmcp = {"command": "atpmcp"}' ~/.claude/claude_code_config.json) && echo "$tmp" > ~/.claude/claude_code_config.json
```

Once configured, Claude Code will have access to the `create_record_cid` tool and can compute CIDs for AT Protocol records during conversations.

### Example usage in Claude Code

Ask Claude to compute a CID:

> What is the CID for this AT Protocol record?
> ```json
> {
>   "$type": "app.bsky.feed.post",
>   "text": "Hello AT Protocol!",
>   "createdAt": "2024-01-01T00:00:00.000Z"
> }
> ```

Claude will call the `create_record_cid` tool and return the CID string.

## Protocol Details

The server implements the MCP stdio transport:

- **stdin**: Receives newline-delimited JSON-RPC 2.0 messages
- **stdout**: Sends newline-delimited JSON-RPC 2.0 responses
- **stderr**: Tracing/logging output (controlled by `RUST_LOG` environment variable)

Supported methods:

| Method | Description |
|--------|-------------|
| `initialize` | MCP handshake, returns server capabilities |
| `ping` | Health check |
| `tools/list` | Lists available tools |
| `tools/call` | Invokes a tool by name |

## License

MIT License
