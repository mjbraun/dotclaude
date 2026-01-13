# dotclaude

Matt's Claude Code configuration - CLAUDE.md, skills, and MCP servers.

## Quick Setup

```bash
curl -sSL https://raw.githubusercontent.com/mjbraun/dotclaude/main/setup.sh | bash
```

This will:
- Clone this repo to `~/.claude`
- Configure the [private-journal](https://github.com/obra/private-journal-mcp) MCP server
- Set up custom skills

## What's Included

- **CLAUDE.md** - Instructions and preferences for Claude
- **skills/** - Custom slash commands
- **mcp-servers/** - Custom MCP servers (frida, mitmproxy, etc.)

## Manual Setup

```bash
git clone https://github.com/mjbraun/dotclaude ~/.claude
~/.claude/setup.sh
```
