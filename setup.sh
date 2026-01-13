#!/bin/bash
# ABOUTME: Bootstrap script for Matt's Claude Code environment
# ABOUTME: Installs CLAUDE.md, skills, and MCP servers (including private-journal)

set -e

REPO_URL="https://github.com/mjbraun/dotclaude.git"
CLAUDE_DIR="$HOME/.claude"
DOTCLAUDE_DIR="$HOME/.dotclaude"  # Separate location for repo

echo "==> Setting up Claude Code environment..."

# Clone or update the dotclaude repo to a SEPARATE location
if [ -d "$DOTCLAUDE_DIR/.git" ]; then
  echo "==> Updating existing dotclaude repo..."
  git -C "$DOTCLAUDE_DIR" pull --ff-only
else
  if [ -d "$DOTCLAUDE_DIR" ]; then
    rm -rf "$DOTCLAUDE_DIR"
  fi
  echo "==> Cloning dotclaude repo..."
  git clone "$REPO_URL" "$DOTCLAUDE_DIR"
fi

# Ensure ~/.claude exists
mkdir -p "$CLAUDE_DIR"

# Symlink or copy specific files (non-destructive)
for file in CLAUDE.md; do
  if [ -f "$DOTCLAUDE_DIR/$file" ]; then
    # Backup existing if it's not already a symlink to our file
    if [ -f "$CLAUDE_DIR/$file" ] && [ ! -L "$CLAUDE_DIR/$file" ]; then
      echo "==> Backing up existing $file to $file.local"
      mv "$CLAUDE_DIR/$file" "$CLAUDE_DIR/$file.local"
    fi
    ln -sf "$DOTCLAUDE_DIR/$file" "$CLAUDE_DIR/$file"
    echo "==> Linked $file"
  fi
done

# Symlink skills directory (merge-friendly approach)
if [ -d "$DOTCLAUDE_DIR/skills" ]; then
  mkdir -p "$CLAUDE_DIR/skills"
  for skill in "$DOTCLAUDE_DIR/skills"/*; do
    if [ -e "$skill" ]; then
      skillname=$(basename "$skill")
      # Backup existing skill if it's not a symlink
      if [ -e "$CLAUDE_DIR/skills/$skillname" ] && [ ! -L "$CLAUDE_DIR/skills/$skillname" ]; then
        echo "==> Backing up existing skill: $skillname"
        mv "$CLAUDE_DIR/skills/$skillname" "$CLAUDE_DIR/skills/$skillname.local"
      fi
      ln -sf "$skill" "$CLAUDE_DIR/skills/$skillname"
      echo "==> Linked skill: $skillname"
    fi
  done
fi

# Symlink commands directory if it exists
if [ -d "$DOTCLAUDE_DIR/commands" ]; then
  mkdir -p "$CLAUDE_DIR/commands"
  for cmd in "$DOTCLAUDE_DIR/commands"/*; do
    if [ -e "$cmd" ]; then
      cmdname=$(basename "$cmd")
      if [ -e "$CLAUDE_DIR/commands/$cmdname" ] && [ ! -L "$CLAUDE_DIR/commands/$cmdname" ]; then
        echo "==> Backing up existing command: $cmdname"
        mv "$CLAUDE_DIR/commands/$cmdname" "$CLAUDE_DIR/commands/$cmdname.local"
      fi
      ln -sf "$cmd" "$CLAUDE_DIR/commands/$cmdname"
      echo "==> Linked command: $cmdname"
    fi
  done
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
  claude mcp add-json private-journal '{"type":"stdio","command":"npx","args":["github:obra/private-journal-mcp"]}' -s user
2>/dev/null || true
else
  echo "WARN: 'claude' CLI not found - skipping MCP server setup"
  echo "      Run this after installing Claude Code:"
  echo "      claude mcp add-json private-journal
'{\"type\":\"stdio\",\"command\":\"npx\",\"args\":[\"github:obra/private-journal-mcp\"]}' -s user"
fi

echo ""
echo "==> Setup complete!"
echo "    Repo:      $DOTCLAUDE_DIR"
echo "    CLAUDE.md: $CLAUDE_DIR/CLAUDE.md -> $DOTCLAUDE_DIR/CLAUDE.md"
echo "    Skills:    $CLAUDE_DIR/skills/"
echo ""
echo "    Local settings preserved in: $CLAUDE_DIR/settings.json"
echo "    To update, run this script again or: git -C $DOTCLAUDE_DIR pull"
echo ""
