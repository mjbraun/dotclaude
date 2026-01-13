#!/bin/bash
# ABOUTME: Wrapper script for pyghidra-mcp MCP server
# ABOUTME: Launches headless Ghidra analysis for firmware binaries

export GHIDRA_INSTALL_DIR="/opt/homebrew/opt/ghidra/libexec"
export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

# Default to X1S hub firmware if no path provided
FIRMWARE="${1:-/tmp/firmware/x1s_hub_v5_20250314_1001.bin}"

exec python3 -m pyghidra_mcp.server \
    --project-name "sofabaton" \
    --project-directory "/tmp/ghidra_project" \
    "$FIRMWARE"
