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

# Sprite-specific: Add tailscale docs to CLAUDE.md
if [ "$USER" = "sprite" ]; then
  echo "==> Detected sprite environment, adding tailscale docs to CLAUDE.md..."
  # Convert symlink to real file so we can append
  if [ -L "$CLAUDE_DIR/CLAUDE.md" ]; then
    cp --remove-destination "$(readlink -f "$CLAUDE_DIR/CLAUDE.md")" "$CLAUDE_DIR/CLAUDE.md"
  fi
  # Append tailscale section if not already present
  if ! grep -q "Tailscale in Sprites" "$CLAUDE_DIR/CLAUDE.md" 2>/dev/null; then
    cat >> "$CLAUDE_DIR/CLAUDE.md" << 'TAILSCALE_EOF'

## Tailscale in Sprites

Sprites run in containers without systemd, so Tailscale won't auto-start and won't restart if it crashes.

**Important**: Even with tailscale running, the sprite won't be reachable until a reusable, tagged auth key is added to your Tailscale ACL with the appropriate permissions. Ask Matt to configure this if needed.

### Check if Tailscale is running

```bash
tailscale status
```

If you get "failed to connect to local tailscaled", the daemon isn't running.

### Quick start (if already authenticated)

```bash
sudo tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
```

### First-time setup (requires human for browser auth)

1. Start the daemon:
```bash
sudo tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
```

2. Authenticate (opens browser URL):
```bash
sudo tailscale up --hostname=YOUR-HOSTNAME
```

3. Optional - serve a local port via HTTPS:
```bash
sudo tailscale serve --bg --https=443 http://127.0.0.1:8000
```

### Auto-restart setup

Create `~/.local/bin/tailscaled-supervisor`:

```bash
#!/bin/bash
# ABOUTME: Keeps tailscaled running, restarts on crash with backoff

ARGS="--state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock"
PIDFILE="/var/run/tailscale/tailscaled-supervisor.pid"

[ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null && exit 0

if [ "$1" != "--fg" ]; then
    nohup "$0" --fg >> /var/log/tailscaled-supervisor.log 2>&1 &
    echo $! | sudo tee "$PIDFILE" > /dev/null
    exit 0
fi

echo $$ | sudo tee "$PIDFILE" > /dev/null
trap 'sudo pkill -x tailscaled; sudo rm -f "$PIDFILE"; exit 0' SIGTERM SIGINT

while true; do
    pgrep -x tailscaled > /dev/null || { sudo tailscaled $ARGS & sleep 3; }
    sleep 10
done
```

Make executable and add to `~/.zshrc`:

```bash
chmod +x ~/.local/bin/tailscaled-supervisor

echo 'if [ -x "$HOME/.local/bin/tailscaled-supervisor" ]; then
    "$HOME/.local/bin/tailscaled-supervisor" 2>/dev/null
fi' >> ~/.zshrc
```

### Troubleshooting

- DNS warnings about /etc/resolv.conf: Normal in containers - networking still works
- Kill daemon only (not supervisor): `sudo pkill -x tailscaled`
- View supervisor log: `cat /var/log/tailscaled-supervisor.log`
TAILSCALE_EOF
    echo "==> Added tailscale documentation section"
  fi
fi

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

# Ensure gh (GitHub CLI) is available
if ! command -v gh &> /dev/null; then
  echo "==> Installing GitHub CLI (gh)..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y gh
  elif command -v brew &> /dev/null; then
    brew install gh
  else
    echo "WARN: Cannot install gh - please install manually"
  fi
fi

# Ensure jq is available
if ! command -v jq &> /dev/null; then
  echo "==> Installing jq..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y jq
  elif command -v brew &> /dev/null; then
    brew install jq
  else
    echo "WARN: Cannot install jq - please install manually"
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

# Configure local settings.json (append, don't overwrite)
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
echo "==> Configuring local settings..."
if command -v jq &> /dev/null; then
  if [ -f "$SETTINGS_FILE" ]; then
    # Merge into existing settings
    jq '. + {"includeCoAuthoredBy": false}' "$SETTINGS_FILE" > "$SETTINGS_FILE.tmp" && mv "$SETTINGS_FILE.tmp" "$SETTINGS_FILE"
  else
    # Create new settings file
    echo '{"includeCoAuthoredBy": false}' | jq . > "$SETTINGS_FILE"
  fi
  echo "==> Set includeCoAuthoredBy: false in settings.json"
else
  echo "WARN: Skipping settings.json configuration (jq not available)"
fi

# Fix OSC escape sequences to use ST instead of BEL (prevents bells through mosh)
fix_bashrc_osc() {
  if [[ -f ~/.bashrc ]]; then
    # Replace \007 (BEL) with \033\\ (ST) in OSC sequences
    if grep -q '\\007' ~/.bashrc; then
      echo "==> Fixing OSC escape sequences in .bashrc (BEL -> ST)..."
      sed -i.bak 's/\\007/\\033\\\\/g' ~/.bashrc
      echo "    Backup saved to ~/.bashrc.bak"
    fi
  fi
}
fix_bashrc_osc

# Move readline bind commands from .bashrc to .inputrc (prevents gibberish on login)
fix_readline_binds() {
  if [[ -f ~/.bashrc ]] && grep -q "^bind '\"" ~/.bashrc; then
    echo "==> Moving readline binds from .bashrc to .inputrc..."
    # Remove bind commands from .bashrc
    sed -i 's/^bind.*history-search-backward.*$//' ~/.bashrc
    sed -i 's/^bind.*history-search-forward.*$//' ~/.bashrc
    # Clean up empty lines left behind
    sed -i '/^$/N;/^\n$/d' ~/.bashrc
  fi
  # Add to .inputrc if not already present
  if ! grep -q 'history-search-backward' ~/.inputrc 2>/dev/null; then
    echo "==> Adding history search bindings to .inputrc..."
    cat >> ~/.inputrc << 'EOF'
"\e[A": history-search-backward
"\e[B": history-search-forward
EOF
  fi
}
fix_readline_binds

echo ""
echo "==> Setup complete!"
echo "    Repo:      $DOTCLAUDE_DIR"
echo "    CLAUDE.md: $CLAUDE_DIR/CLAUDE.md -> $DOTCLAUDE_DIR/CLAUDE.md"
echo "    Skills:    $CLAUDE_DIR/skills/"
echo ""
echo "    Local settings preserved in: $CLAUDE_DIR/settings.json"
echo "    To update, run this script again or: git -C $DOTCLAUDE_DIR pull"
echo ""
