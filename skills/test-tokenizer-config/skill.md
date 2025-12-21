# Test Tokenizer Config

Test the tokenizer configuration by verifying it can correctly unseal tokens encrypted with the SEAL_KEY.

## Purpose

This skill validates that:
- The tokenizer is running and accessible
- The SEAL_KEY is correctly configured
- The tokenizer can decrypt sealed tokens
- End-to-end token flow works

## How to Use

When the user requests to test the tokenizer configuration:

1. Start a simple HTTP listener on a test port (e.g., 9999)
2. Encrypt a test value using the same encryption method as ssokenizer
3. Send a request through the tokenizer proxy with the encrypted value
4. Verify the HTTP listener receives the decrypted value

## Implementation

### Step 1: Start HTTP Test Server

Create a simple HTTP server that echoes back the Authorization header:

```bash
# Start a simple HTTP server on port 9999 that returns request headers
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get('Authorization', 'NO AUTH')
        response = json.dumps({'authorization': auth, 'path': self.path})
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(response.encode())
        print(f'Received Authorization: {auth}')

    def log_message(self, format, *args):
        pass  # Suppress default logging

server = HTTPServer(('localhost', 9999), Handler)
print('Test server listening on port 9999')
server.serve_forever()
" > /tmp/test-server.log 2>&1 &

echo $!
```

### Step 2: Encrypt Test Value

Use the ssokenizer to encrypt a test token value:

```bash
cd /Users/mjbraun/dev/superfly/ssokenizer

# Create a test token value
TEST_TOKEN="Bearer test-token-12345"

# Use ssokenizer to seal the token
SEALED=$(SEAL_KEY="6ffe668215632916e07f8af91b506dd459c05af1f82363070428828855afee2d" \
  /opt/homebrew/bin/go run ./cmd/ssokenizer seal --input "$TEST_TOKEN")

echo "Test token: $TEST_TOKEN"
echo "Sealed token: $SEALED"

# Save sealed token for use
echo "$SEALED" > /tmp/test_sealed_token.txt
```

### Step 3: Test Request Through Tokenizer

Make a request through the tokenizer proxy to verify it unseals correctly:

```bash
SEALED_TOKEN=$(cat /tmp/test_sealed_token.txt)

curl -v \
  -x http://localhost:8080 \
  -H "Proxy-Tokenizer: $SEALED_TOKEN" \
  http://localhost:9999/test 2>&1 | grep -A 5 "authorization"
```

### Step 4: Verify Results

The HTTP server should receive the decrypted `Bearer test-token-12345` in the Authorization header, NOT the sealed version.

**Success criteria:**
- HTTP server receives `{"authorization": "Bearer test-token-12345", ...}`
- NOT the sealed/encrypted value

**Failure indicators:**
- Server receives sealed token directly (tokenizer not unsealing)
- Connection refused (tokenizer not running)
- 502/407 errors (configuration issue)

## Alternative: Simple Base64 Test

If ssokenizer doesn't have a seal command, use a simpler approach:

```bash
# Start test server
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        proxy_tok = self.headers.get('Proxy-Tokenizer', '')
        auth = self.headers.get('Authorization', '')
        print(f'Proxy-Tokenizer: {proxy_tok[:50]}...')
        print(f'Authorization: {auth}')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(f'Auth: {auth}'.encode())

server = HTTPServer(('localhost', 9999), Handler)
print('Listening on :9999')
server.serve_forever()
" &

TEST_PID=$!

# Wait for server
sleep 2

# Use existing sealed token from database
SEALED_TOKEN=$(cat /tmp/vanta_sealed_token.txt)

# Make request
curl -v \
  -x http://localhost:8080 \
  -H "Proxy-Tokenizer: $SEALED_TOKEN" \
  http://localhost:9999/test

# Cleanup
kill $TEST_PID
```

## Troubleshooting

### Tokenizer not unsealing
- Check SEAL_KEY matches between ssokenizer and tokenizer
- Verify `6ffe668215632916e07f8af91b506dd459c05af1f82363070428828855afee2d`

### Connection refused
- Tokenizer not running: `lsof -ti:8080`
- Start with: `LISTEN_ADDRESS=":8080" SEAL_KEY="..." OPEN_PROXY=1 OPEN_KEY="..." go run cmd/tokenizer/main.go`

### 407 Proxy Auth Required
- Need OPEN_PROXY=1 and OPEN_KEY set for dev mode

## Cleanup

Kill test server:
```bash
lsof -ti:9999 | xargs kill
```
