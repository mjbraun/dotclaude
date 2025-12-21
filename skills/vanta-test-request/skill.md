# Vanta Test Request

Test the complete tokenizer/ssokenizer flow by making a read-only request to the Vanta API.

## Purpose

This skill makes a test request to Vanta's API through the tokenizer to verify:
- Sealed token can be retrieved from database
- Tokenizer is running and accessible
- Tokenizer can unseal the token
- Proxy configuration is correct
- API request succeeds

## How to Use

When the user requests to test Vanta integration:

1. Retrieve the sealed token from the database
2. Make a read-only GET request to Vanta's `/whoami` or `/ping` endpoint
3. Send the request through the tokenizer proxy
4. Display the response to verify everything works

## Implementation

### Step 1: Get Sealed Token

```bash
DATABASE_PORT=59169 USAGE_DATABASE_PORT=59167 mix run -e '
org = Fly.Organizations.get_organization_by(slug: "vanta-test")
sealed_token = org.tokenized_vanta_token
File.write!("/tmp/vanta_sealed_token.txt", sealed_token)
IO.puts("Sealed token saved to /tmp/vanta_sealed_token.txt")
'
```

### Step 2: Make Test Request via Tokenizer

```bash
SEALED_TOKEN=$(cat /tmp/vanta_sealed_token.txt | tr -d '\n')

curl -v \
  -x http://localhost:8080 \
  -H "Proxy-Authorization: Bearer dev-tokenizer-auth" \
  -H "Proxy-Tokenizer: $SEALED_TOKEN" \
  -H "Content-Type: application/json" \
  http://api.vanta.com/v1/whoami
```

**Important:** The `Proxy-Authorization` header MUST match the `secret_auth.bearer` value configured in ssokenizer's `dev-config.yml`. In dev mode, this is `dev-tokenizer-auth`. This bearer token is embedded in the sealed token during encryption and must match during decryption.

## Expected Response

A successful response should return:
- HTTP 200 status code
- JSON response with Vanta account information

Example:
```json
{
  "id": "...",
  "displayName": "...",
  "email": "..."
}
```

## Error Handling

### "failed Proxy-Tokenizer decryption"
- **Cause:** SEAL_KEY mismatch between ssokenizer and tokenizer
- **Fix:** Verify both use `6ffe668215632916e07f8af91b506dd459c05af1f82363070428828855afee2d`

### "bad or missing proxy auth" (HTTP 407)
- **Cause:** The `Proxy-Authorization` bearer token doesn't match the `secret_auth.bearer` value in ssokenizer's config
- **Fix in Dev:** Ensure you're using `Proxy-Authorization: Bearer dev-tokenizer-auth` (from dev-config.yml)
- **Fix in Production:** Use the correct bearer token configured in the production ssokenizer config
- **Technical Details:** The bearer token is embedded in the sealed token during encryption and validated during decryption by comparing SHA256 hashes (see authorizer.go:102-110)

### Connection refused
- **Cause:** Tokenizer not running on port 8080
- **Fix:** Check `lsof -ti:8080` and start tokenizer if needed

### HTTP 401 Unauthorized
- **Cause:** Token expired or invalid
- **Fix:** Re-link Vanta OAuth to get fresh token

## Alternative Test Endpoints

If `/whoami` doesn't exist, try:
- `GET http://api.vanta.com/v1/user` - Get current user
- `GET http://api.vanta.com/v1/organizations` - List organizations

## Verification Steps

1. **Check tokenizer is running:**
   ```bash
   lsof -ti:8080 && echo "Tokenizer running" || echo "Tokenizer not running"
   ```

2. **Check ssokenizer is running:**
   ```bash
   lsof -ti:3000 && echo "Ssokenizer running" || echo "Ssokenizer not running"
   ```

3. **Verify SEAL_KEY in tokenizer logs:**
   ```bash
   grep "seal_key" /tmp/tokenizer.log
   ```

4. **Verify sealed token exists in database:**
   Run the vanta-get-sealed-token skill first

## Success Criteria

- Tokenizer accepts the sealed token
- Tokenizer successfully unseals it
- Vanta API returns valid JSON response
- No HTTP errors (407, 502, etc.)
