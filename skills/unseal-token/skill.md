# Unseal Token Skill

This skill unseals tokenized secrets stored in the database using the local unsealing utility.

## When to use this skill

Use this skill when you need to:
- View the actual OAuth tokens stored in sealed form in the database
- Debug token issues by examining the unsealed token values
- Verify that tokens were correctly sealed and can be unsealed

## How to use this skill

1. Get the sealed token from the database (usually stored in `tokenized_vanta_token` or similar field)
2. Run the unseal command with the OPEN_KEY from the tokenizer configuration

## Example usage

```bash
# Get the sealed token from database
cd ~/dev/superfly/ui-ex
DATABASE_PORT=5432 USAGE_DATABASE_PORT=6432 mix run -e 'org = Fly.Organizations.get_organization_by(slug: "vanta-test"); IO.puts(org.tokenized_vanta_token)'

# Unseal the token (sources OPEN_KEY from .envrc)
cd ~/dev/superfly/tokenizer/cmd/unsealtoken
source ../tokenizer/.envrc && /opt/homebrew/bin/go run . "<sealed-token-here>"
```

## Configuration

The OPEN_KEY is stored in `/Users/mjbraun/dev/superfly/tokenizer/cmd/tokenizer/.envrc`.
Source it before running the unseal command - never hardcode the key.

## Output format

The command outputs a JSON object containing:
- `AuthConfig`: Authentication configuration including digest
- `ProcessorConfig`: The token processor configuration with the actual OAuth tokens
  - `token.access_token`: The unsealed access token
  - `token.refresh_token`: The unsealed refresh token (if present)
- `RequestValidators`: Any request validators configured

## Security note

The unsealed tokens are sensitive credentials. Only use this tool in development environments and never commit unsealed tokens to version control.
