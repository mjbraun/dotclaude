# HTTP Debug Proxy

Set up and manage an intercepting HTTP/HTTPS proxy for debugging OAuth flows and API requests.

## Overview

This skill uses `mitmproxy` to intercept and inspect all HTTP/HTTPS traffic between:
- Browser ↔ Phoenix
- Phoenix ↔ SSokenizer
- SSokenizer ↔ Vanta API
- Any service ↔ Tokenizer

## Prerequisites

Check if mitmproxy is installed:
```bash
which mitmweb || echo "Not installed"
```

If not installed:
```bash
brew install mitmproxy
```

## Starting the Proxy

Start mitmproxy with web interface:
```bash
mitmweb --listen-port 8888 --web-port 8889 > /tmp/mitmproxy.log 2>&1 &
```

**Ports:**
- `8888`: Proxy port (services and browser connect here)
- `8889`: Web UI at http://localhost:8889

Verify it started:
```bash
lsof -ti:8888 && echo "Proxy running" || echo "Proxy not running"
```

## Configuring Services

### 1. SSokenizer (Go application)

SSokenizer needs to use the proxy for outbound requests to Vanta:

```bash
cd ~/dev/superfly/ssokenizer && \
export VANTA_CLIENT_ID="${VANTA_CLIENT_ID:-vci_6cc939d937d96c1cc9a34c1bb44e83220018c709fcf5d7f2}" && \
export VANTA_CLIENT_SECRET="${VANTA_CLIENT_SECRET:-$(op read 'op://Dev/gi5qxfdi6rgv3tgz2qnr6wmpnm/credential' --account flyio)}" && \
export HTTP_PROXY="http://localhost:8888" && \
export HTTPS_PROXY="http://localhost:8888" && \
/opt/homebrew/bin/go run ./cmd/ssokenizer serve --config dev-config.yml > /tmp/ssokenizer.log 2>&1 &
```

### 2. Phoenix (Elixir application)

Phoenix HTTP client (Req) can use proxy via environment variables:

```bash
cd ~/dev/superfly/ui-ex && \
export SSOKENIZER_URL="https://judgeless-pleasantly-tammera.ngrok-free.dev" && \
export DATABASE_PORT=5432 && \
export USAGE_DATABASE_PORT=6432 && \
export HTTP_PROXY="http://localhost:8888" && \
export HTTPS_PROXY="http://localhost:8888" && \
mix phx.server > /tmp/phoenix.log 2>&1 &
```

### 3. Tokenizer (Go application)

```bash
cd ~/dev/superfly/tokenizer/cmd/tokenizer && \
source .envrc && \
export HTTP_PROXY="http://localhost:8888" && \
export HTTPS_PROXY="http://localhost:8888" && \
/opt/homebrew/bin/go run . > /tmp/tokenizer.log 2>&1 &
```

### 4. Browser Configuration

**Manual Proxy Settings:**
1. Open System Settings → Network → Advanced → Proxies
2. Enable "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
3. Set both to: `localhost` port `8888`
4. Click OK and Apply

**Or use browser extension** like FoxyProxy for easier switching.

## Installing SSL Certificate

For HTTPS interception, install mitmproxy's certificate:

1. Start mitmproxy and set browser proxy
2. Navigate to: http://mitm.it
3. Click your OS/browser and install the certificate
4. macOS: Add to Keychain, then trust it (open Keychain Access, find "mitmproxy", set to "Always Trust")

## Viewing Traffic

**Web Interface:** http://localhost:8889

Shows:
- All HTTP requests and responses
- Headers, body, timing
- Filter by host, method, status
- Replay requests

**Useful filters in web UI:**
- `~d api.vanta.com` - Only Vanta API requests
- `~d localhost:3000` - Only SSokenizer requests
- `~m POST` - Only POST requests
- `~u /oauth/` - URLs containing "/oauth/"

## Complete Debug Session

When user requests proxy debugging:

1. **Install if needed:**
   ```bash
   brew list mitmproxy || brew install mitmproxy
   ```

2. **Start proxy:**
   ```bash
   mitmweb --listen-port 8888 --web-port 8889 > /tmp/mitmproxy.log 2>&1 &
   sleep 3
   lsof -ti:8888 && echo "✓ Proxy running on port 8888" || echo "✗ Failed to start"
   ```

3. **Stop all services:**
   ```bash
   kill $(lsof -ti:3000) 2>/dev/null; # SSokenizer
   kill $(lsof -ti:4000) 2>/dev/null; # Phoenix
   kill $(lsof -ti:8080) 2>/dev/null; # Tokenizer
   sleep 2
   ```

4. **Restart with proxy** (in order):
   ```bash
   # Tokenizer
   cd ~/dev/superfly/tokenizer/cmd/tokenizer && \
   source .envrc && \
   export HTTP_PROXY="http://localhost:8888" && \
   export HTTPS_PROXY="http://localhost:8888" && \
   /opt/homebrew/bin/go run . > /tmp/tokenizer.log 2>&1 &

   sleep 3

   # SSokenizer
   cd ~/dev/superfly/ssokenizer && \
   export VANTA_CLIENT_ID="${VANTA_CLIENT_ID:-vci_6cc939d937d96c1cc9a34c1bb44e83220018c709fcf5d7f2}" && \
   export VANTA_CLIENT_SECRET="${VANTA_CLIENT_SECRET:-$(op read 'op://Dev/gi5qxfdi6rgv3tgz2qnr6wmpnm/credential' --account flyio)}" && \
   export HTTP_PROXY="http://localhost:8888" && \
   export HTTPS_PROXY="http://localhost:8888" && \
   /opt/homebrew/bin/go run ./cmd/ssokenizer serve --config dev-config.yml > /tmp/ssokenizer.log 2>&1 &

   sleep 3

   # Phoenix
   cd ~/dev/superfly/ui-ex && \
   export SSOKENIZER_URL="https://judgeless-pleasantly-tammera.ngrok-free.dev" && \
   export DATABASE_PORT=5432 && \
   export USAGE_DATABASE_PORT=6432 && \
   export HTTP_PROXY="http://localhost:8888" && \
   export HTTPS_PROXY="http://localhost:8888" && \
   mix phx.server > /tmp/phoenix.log 2>&1 &
   ```

5. **Verify services:**
   ```bash
   echo "=== Service Status ==="
   lsof -ti:8080 && echo "✓ Tokenizer (8080)" || echo "✗ Tokenizer"
   lsof -ti:3000 && echo "✓ SSokenizer (3000)" || echo "✗ SSokenizer"
   lsof -ti:4000 && echo "✓ Phoenix (4000)" || echo "✗ Phoenix"
   lsof -ti:8888 && echo "✓ Proxy (8888)" || echo "✗ Proxy"
   ```

6. **Inform user:**
   - Set browser proxy to `localhost:8888`
   - Visit http://mitm.it to install certificate
   - Open http://localhost:8889 to view traffic
   - Test OAuth flow at http://localhost:4000/dashboard/vanta-test/compliance

## Querying Request History

The mitmproxy instances write flows to `/tmp/mitmproxy_flows.jsonl` in JSONL format (one JSON object per line).

### List Recent Requests

Show the last N requests:
```bash
tail -<N> /tmp/mitmproxy_flows.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    flow = json.loads(line)
    if flow.get('type') == 'request':
        print(f\"{flow.get('timestamp')} {flow.get('method')} {flow.get('url')}\")
"
```

### Filter by Host

Show requests to a specific host (e.g., api.vanta.com):
```bash
grep '"host": "api.vanta.com"' /tmp/mitmproxy_flows.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    flow = json.loads(line)
    print(f\"{flow.get('timestamp')} {flow.get('type')} {flow.get('method', 'N/A')} {flow.get('url')}\")
"
```

### Get Full Request Details

Show a specific request with all details (use ID from above):
```bash
grep '"id": "<flow-id>"' /tmp/mitmproxy_flows.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    flow = json.loads(line)
    if flow.get('type') == 'request':
        print('=' * 80)
        print(f\"Request: {flow.get('method')} {flow.get('url')}\")
        print(f\"Timestamp: {flow.get('timestamp')}\")
        print(f\"Headers: {json.dumps(flow.get('headers', {}), indent=2)}\")
        if 'content' in flow:
            print(f\"Body: {flow['content']}\")
    elif flow.get('type') == 'response':
        print('=' * 80)
        print(f\"Response Status: {flow.get('status_code')}\")
        print(f\"Headers: {json.dumps(flow.get('headers', {}), indent=2)}\")
        if 'content' in flow:
            print(f\"Body: {flow.get('content', '')}\")
    print('=' * 80)
"
```

### Find Requests by Path Pattern

Find all requests matching a path pattern (e.g., /oauth/token/suspend):
```bash
grep -i 'suspend' /tmp/mitmproxy_flows.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    flow = json.loads(line)
    print(f\"{flow.get('id')} {flow.get('timestamp')} {flow.get('type')} {flow.get('method', '')} {flow.get('url', '')} status={flow.get('status_code', 'N/A')}\")
"
```

### Get Request/Response Pair by ID

Once you have a flow ID, get both request and response:
```bash
FLOW_ID="<id-here>"
grep "\"id\": \"$FLOW_ID\"" /tmp/mitmproxy_flows.jsonl | python3 -c "
import sys, json

request_flow = None
response_flow = None

for line in sys.stdin:
    flow = json.loads(line)
    if flow.get('type') == 'request':
        request_flow = flow
    elif flow.get('type') == 'response':
        response_flow = flow

if request_flow:
    print('=' * 80)
    print('REQUEST')
    print('=' * 80)
    print(f\"Method: {request_flow.get('method')}\")
    print(f\"URL: {request_flow.get('url')}\")
    print(f\"Timestamp: {request_flow.get('timestamp')}\")
    print(f\"Headers:\")
    for k, v in request_flow.get('headers', {}).items():
        print(f\"  {k}: {v}\")
    if 'content' in request_flow and request_flow['content']:
        print(f\"\nBody:\n{request_flow['content']}\")
    print()

if response_flow:
    print('=' * 80)
    print('RESPONSE')
    print('=' * 80)
    print(f\"Status: {response_flow.get('status_code')} {response_flow.get('reason', '')}\")
    print(f\"Timestamp: {response_flow.get('timestamp')}\")
    print(f\"Headers:\")
    for k, v in response_flow.get('headers', {}).items():
        print(f\"  {k}: {v}\")
    if 'content' in response_flow and response_flow['content']:
        print(f\"\nBody:\n{response_flow['content']}\")
    print('=' * 80)
"
```

## Stopping the Proxy

```bash
kill $(lsof -ti:8888) 2>/dev/null
rm /tmp/mitmproxy.log
```

Don't forget to disable browser proxy settings afterward!

## Troubleshooting

**Certificate issues:**
- Make sure certificate is installed and trusted
- Some apps ignore system proxy settings (curl has `--proxy` flag)
- Go apps respect HTTP_PROXY/HTTPS_PROXY environment variables

**Proxy not intercepting:**
- Check logs: `tail -50 /tmp/mitmproxy.log`
- Verify services started with proxy env vars: `ps eww <pid> | grep HTTP_PROXY`
- Some services may need explicit proxy config in code

**SSL errors:**
- Go: Set `export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem`
- Or disable verification (dev only!): `export GODEBUG=http2client=0`
