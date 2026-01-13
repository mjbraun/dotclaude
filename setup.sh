#!/bin/bash
# ABOUTME: Bootstrap script for Matt's Claude Code environment
# ABOUTME: Installs CLAUDE.md, skills, and MCP servers (including private-journal)

set -e

REPO_URL="https://github.com/mjbraun/dotclaude.git"
CLAUDE_DIR="$HOME/.claude"

echo "==> Setting up Claude Code environment..."

# Clone or update the dotclaude repo
if [ -d "$CLAUDE_DIR/.git" ]; then
    echo "==> Updating existing dotclaude repo..."
    git -C "$CLAUDE_DIR" pull --ff-only
else
    if [ -d "$CLAUDE_DIR" ]; then
        echo "==> ~/.claude exists but isn't a git repo, backing up..."
        mv "$CLAUDE_DIR" "$CLAUDE_DIR.backup.$(date +%s)"
    fi
    echo "==> Cloning dotclaude repo..."
    git clone "$REPO_URL" "$CLAUDE_DIR"
fi

# Ensure Node.js/npx is available (needed for private-journal)
if ! command -v npx &> /dev/null; then
    echo "==> Installing Node.js..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y nodejs npm
    elif command -v brew &> /dev/null; then
        brew install node
    else
        echo "ERROR: Cannot install Node.js - please install manually"
        exit 1
    fi
fi

# Add private-journal MCP server
echo "==> Configuring private-journal MCP server..."
if command -v claude &> /dev/null; then
    claude mcp add-json private-journal '{"type":"stdio","command":"npx","args":["github:obra/private-journal-mcp"]}' -s user 2>/dev/null || true
else
    echo "WARN: 'claude' CLI not found - skipping MCP server setup"
    echo "      Run this after installing Claude Code:"
    echo "      claude mcp add-json private-journal '{\"type\":\"stdio\",\"command\":\"npx\",\"args\":[\"github:obra/private-journal-mcp\"]}' -s user"
fi

echo ""
echo "==> Setup complete!"
echo "    CLAUDE.md: $CLAUDE_DIR/CLAUDE.md"
echo "    Skills:    $CLAUDE_DIR/skills/"
echo ""
