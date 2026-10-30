"""Adapters that put Tripwire between real agents and their tools.

claude_code  Claude Code hooks (`tripwire hook <event>`) plus the settings.json installer
mcp_proxy    stdio MCP proxy (`tripwire mcp-proxy -- <server cmd>`)
pins         signed tool metadata pins for MCP servers (rug-pull / tool-poisoning defence)
"""
