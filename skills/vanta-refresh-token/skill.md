# Vanta Refresh Token

Refresh the Vanta OAuth token for an organization.

## Purpose

This skill refreshes an expired or expiring Vanta OAuth token for a Fly organization by calling the ssokenizer refresh endpoint through the tokenizer proxy.

## How to Use

When the user requests to refresh a Vanta token for an organization:

1. Get the organization by slug
2. Verify the organization is linked to Vanta
3. Call the refresh endpoint through the tokenizer
4. Update the organization with the new sealed token

## Implementation

### Step 1: Get Organization and Verify

```bash
DATABASE_PORT=62628 USAGE_DATABASE_PORT=62626 SSOKENIZER_URL="http://localhost:3000" mix run -e '
org = Fly.Organizations.get_organization_by(slug: "ORGSLUG")
if org.vanta_linked do
  IO.puts("Organization is linked, proceeding with refresh...")
  IO.puts("Current token expires: #{org.tokenized_vanta_token_expires}")
else
  IO.puts("Error: Organization is not linked to Vanta")
end
'
```

### Step 2: Refresh Token via Elixir

```bash
DATABASE_PORT=62628 USAGE_DATABASE_PORT=62626 SSOKENIZER_URL="http://localhost:3000" mix run -e '
org = Fly.Organizations.get_organization_by(slug: "ORGSLUG")
case Fly.Vanta.Client.refresh_token(org) do
  {:ok, updated_org} ->
    IO.puts("Successfully refreshed token for #{org.slug}")
    IO.puts("New token expires: #{updated_org.tokenized_vanta_token_expires}")
  {:error, reason} ->
    IO.puts("Failed to refresh token: #{inspect(reason)}")
end
'
```

### Alternative: Manual Refresh via cURL

If the Elixir refresh function has issues, you can manually refresh:

```bash
# Step 1: Get the current sealed token
SEALED_TOKEN=$(DATABASE_PORT=62628 USAGE_DATABASE_PORT=62626 mix run -e 'org = Fly.Organizations.get_organization_by(slug: "ORGSLUG"); IO.write(org.tokenized_vanta_token)' 2>/dev/null)

# Step 2: Call the refresh endpoint through tokenizer
curl -v \
  -x http://localhost:8080 \
  -H "Proxy-Authorization: Bearer dev-tokenizer-auth" \
  -H "Proxy-Tokenizer: $SEALED_TOKEN; st=refresh" \
  http://localhost/vanta/refresh > /tmp/new_sealed_token.txt

# Step 3: Extract expiry from Cache-Control header and update database
# (This would need to be implemented based on the response)
```

## Expected Response

A successful refresh should:
- Return HTTP 200
- Return a new sealed token in the response body
- Include a `Cache-Control` header with `max-age` indicating token expiry

Example success output:
```
Successfully refreshed token for vanta-test
New token expires: 1732012345
```

## Error Handling

### "not linked" error
- **Cause:** Organization's `vanta_linked` field is `false`
- **Fix:** Link the organization to Vanta first through the OAuth flow in the UI

### :econnrefused
- **Cause:** Ssokenizer not running on port 3000
- **Fix:** Start ssokenizer with `cd /Users/mjbraun/dev/superfly/ssokenizer && VANTA_CLIENT_ID="..." VANTA_CLIENT_SECRET="..." go run ./cmd/ssokenizer serve --config dev-config.yml`

### "bad or missing proxy auth" (HTTP 407)
- **Cause:** Tokenizer bearer auth mismatch
- **Fix:** Ensure using `Proxy-Authorization: Bearer dev-tokenizer-auth`

### HTTP 401 from Vanta
- **Cause:** Token is invalid or revoked (not just expired)
- **Fix:** Re-link the organization through the OAuth flow

## Verification Steps

1. **Check organization is linked:**
   ```bash
   DATABASE_PORT=62628 USAGE_DATABASE_PORT=62626 mix run -e 'org = Fly.Organizations.get_organization_by(slug: "ORGSLUG"); IO.puts("vanta_linked: #{org.vanta_linked}")'
   ```

2. **Check token expiry:**
   ```bash
   DATABASE_PORT=62628 USAGE_DATABASE_PORT=62626 mix run -e 'org = Fly.Organizations.get_organization_by(slug: "ORGSLUG"); IO.puts("expires: #{org.tokenized_vanta_token_expires}"); IO.puts("current_time: #{System.system_time(:second)}")'
   ```

3. **Verify ssokenizer is running:**
   ```bash
   lsof -ti:3000 && echo "Ssokenizer running" || echo "Ssokenizer not running"
   ```

4. **Verify tokenizer is running:**
   ```bash
   lsof -ti:8080 && echo "Tokenizer running" || echo "Tokenizer not running"
   ```

## Success Criteria

- Token refresh returns {:ok, updated_org}
- New expiry timestamp is greater than current time
- Organization record is updated in database
- Can successfully make API calls to Vanta with the new token
