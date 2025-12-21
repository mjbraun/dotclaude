# Vanta Get Sealed Token

Retrieve the sealed Vanta OAuth token from the database for debugging and testing.

## Purpose

This skill fetches the sealed Vanta token stored in the database for a given organization. This is useful for:
- Verifying that OAuth linking was successful
- Debugging token-related issues
- Testing tokenizer functionality manually

## How to Use

When the user requests to get the Vanta sealed token:

1. Use an Elixir mix command to query the database
2. Extract the sealed token and expiration from the organization record
3. Display the token information to the user

## Implementation

```bash
DATABASE_PORT=59169 USAGE_DATABASE_PORT=59167 mix run -e '
org = Fly.Organizations.get_organization_by(slug: "vanta-test")
IO.puts("Organization: #{org.name}")
IO.puts("Vanta Linked: #{org.vanta_linked}")
IO.puts("Token Expires: #{org.tokenized_vanta_token_expires}")
IO.puts("Sealed Token: #{String.slice(org.tokenized_vanta_token || "nil", 0..100)}...")
'
```

## Output Format

Display:
- Organization name
- Whether Vanta is linked (true/false)
- Token expiration timestamp
- First 100 characters of the sealed token (for security/readability)

## Error Handling

If the organization doesn't exist or token is nil:
- Report that no token was found
- Suggest relinking Vanta OAuth if needed
