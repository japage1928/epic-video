# Epic Video — MCP Server

The public [Model Context Protocol](https://modelcontextprotocol.io) server for
[Epic Video](https://epicvideo.lol): generate short AI videos with sound from
text prompts, with optional locked characters.

- **Remote endpoint:** `https://mcp.epicvideo.lol/mcp` (Streamable HTTP)
- **Registry name:** `io.github.japage1928/epic-video`
- **Discovery:** `initialize` and `tools/list` work without credentials; tool
  calls require an Epic Video account, connected through a standard OAuth 2.0
  authorization-code + PKCE flow with dynamic client registration.

## Tools

| Tool | What it does |
| --- | --- |
| `create_video` | Start a video generation job from a text prompt (optional character / image) |
| `get_job_status` | Check a job and get its result |
| `list_my_videos` | List your generated videos |
| `get_my_usage` | See your plan and token balance |
| `list_characters` | List your locked characters |

## This repository

`mcp_server.py` is the server itself: a single-file, standard-library-only
Python program that serves the MCP endpoint and runs its own OAuth 2.0
authorization server, signing users in with their Epic Video account (email +
password, or Google). Secrets are read from a local `.env` file that is never
committed.

`server.json` is the MCP Registry listing for this server.

## Running your own copy

You don't need to — the hosted endpoint above is the product. The code is
published so clients and directories can verify what the server does.
