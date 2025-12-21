# Dev Environment Manager

Manage the development environment services for the Fly.io stack.

## Services

This skill manages the following services:

1. **fly-tools (web)**: Docker-based web service
2. **tokenizer**: HTTP proxy service that unseals tokens (port 8080)
3. **ssokenizer**: OAuth service that handles Vanta OAuth flows (port 3000)
4. **ngrok**: HTTP tunnel for OAuth callbacks (exposes port 3000 publicly)
5. **ui-ex**: Elixir Phoenix application (port 4000)

## Configuration

The services require the following configuration:

### Tokenizer
- Port: 8080
- Directory: `/Users/mjbraun/dev/superfly/tokenizer`
- Current OPEN_KEY: `a29dcbaa824af8f0a8d435df6ca1f27cfbf1d5aaa03f3f87fa0a58f8a34d8f67`
- Derived seal_key: `6c8792058608dd8cfff94f689664bd25c073057c78b4c665b40fed52538b2867`
- Build command: `cd /Users/mjbraun/dev/superfly/tokenizer && go build -o tokenizer ./cmd/tokenizer`
- Run command: `NO_FLY_SRC=1 OPEN_KEY=a29dcbaa824af8f0a8d435df6ca1f27cfbf1d5aaa03f3f87fa0a58f8a34d8f67 ./tokenizer`
- **IMPORTANT**: Must set `NO_FLY_SRC=1` for local development (tokenizer normally requires `/.fly/fly-src.pub` file which doesn't exist locally)
- Note: OPEN_KEY is a Curve25519 private key. The tokenizer derives the public key (seal_key) from it. The ssokenizer dev-config.yml must use the corresponding seal_key.

### Ssokenizer
- Port: 3000
- Required env vars (fetched from 1Password):
  - `VANTA_CLIENT_ID` - Get from: `op read --account flyio "op://Employee/Vanta Test App/username"`
  - `VANTA_CLIENT_SECRET` - Get from: `op read --account flyio "op://Employee/Vanta Test App/credential"`
- Directory: `/Users/mjbraun/dev/superfly/ssokenizer`
- Config file: `dev-config.yml`
- Command: `/opt/homebrew/bin/go run ./cmd/ssokenizer serve --config dev-config.yml`
- Note: For OAuth to work, the `url` field in dev-config.yml must match the ngrok public URL
- Note: Requires `op` CLI installed and authenticated (`op signin --account flyio`)

### Ngrok
- Port: Tunnels port 3000 to public internet
- Static domain: `https://judgeless-pleasantly-tammera.ngrok-free.dev`
- Command: `ngrok http 3000 > /tmp/ngrok.log 2>&1 &`
- Check tunnel status: `curl -s http://127.0.0.1:4040/api/tunnels | python3 -m json.tool`
- Why needed: OAuth providers (Vanta) need publicly accessible callback URLs
- Static domain persistence: ngrok provides one free static domain that persists across restarts
- Note: The static domain is already configured - if it changes, update both `dev-config.yml` and Phoenix's `SSOKENIZER_URL` env var

### UI-EX
- Port: 4000
- Required env vars:
  - `SSOKENIZER_URL` - **MUST ALWAYS BE**: `"https://judgeless-pleasantly-tammera.ngrok-free.dev"` (NEVER use localhost)
  - `DATABASE_PORT` - Get from `docker ps` (usually 5432)
  - `USAGE_DATABASE_PORT` - Get from `docker ps` (usually 6432)
  - `OBAN_CRON=true` - Enable Oban cron jobs in dev mode (required for scheduled Vanta syncs)
  - `VANTA_CLIENT_ID` - Get from: `op read --account flyio "op://Employee/Vanta Test App/username"`
  - `VANTA_CLIENT_SECRET` - Get from: `op read --account flyio "op://Employee/Vanta Test App/credential"`
- Directory: `/Users/mjbraun/dev/superfly/ui-ex`
- Command (background): `mix phx.server > /tmp/phoenix.log 2>&1 &`
- Command (interactive): `iex -S mix phx.server`
- Auto-detect ports: `docker ps --format "{{.Names}}: {{.Ports}}" | grep -E "(proxy_development-db|usage_development-db)"`
- Note: Use `mix phx.server` (without iex) for background mode. Use `iex -S mix phx.server` for interactive debugging.
- **CRITICAL OAuth requirement**: SSOKENIZER_URL must ALWAYS be the ngrok public URL `https://judgeless-pleasantly-tammera.ngrok-free.dev`. NEVER use `http://localhost:3000` or OAuth will fail with "missing transaction cookie" error!
- **Cron requirement**: Set `OBAN_CRON=true` to enable scheduled jobs (like Vanta user sync) in dev mode

### Fly-Tools (Web)
- Directory: `/Users/mjbraun/dev/superfly/fly-tools`
- Command: `./run-with-web.sh -d`
- Docker containers:
  - `fly-tools-db-1`: PostgreSQL database
  - `fly-tools-cache-1`: Redis cache
  - `fly-tools-timescale-1`: TimescaleDB (usage database)
- Note: Use `docker ps --format "{{.Names}}: {{.Ports}}"` to find mapped ports for UI-EX configuration

## Commands

When the user requests service management:

### Start a service
1. Check if the service is already running on its port using `lsof -ti:<port>`
2. **IMPORTANT for Phoenix (ui-ex)**: If Phoenix is running, verify it's actually responding:
   ```bash
   curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:4000
   ```
   - If returns `200`: Phoenix is healthy
   - If returns `000` or times out: Phoenix is hung, needs restart (see "Restart hung Phoenix" below)
3. If not running:
   - Use the Bash tool with `run_in_background: true` parameter
   - For fly-tools: Check Docker containers with `docker ps --filter "name=fly-tools"`
   - **For tokenizer**:
     - Start with OPEN_KEY environment variable
     - Capture the seal_key from the tokenizer output (it will print the derived public key)
     - Save this seal_key for use in ssokenizer configuration
   - **For ssokenizer**:
     - Must be started AFTER tokenizer
     - Update dev-config.yml with the seal_key that tokenizer output
     - Then start with proper environment variables
   - For other services: Start with proper environment variables in a single command
   - Wait 2-3 seconds after starting
   - Verify the service started by checking the port again or testing with curl
4. Report success with service details

### Stop a service
1. Find processes using the service's port
2. Kill the processes
3. Confirm the service is stopped

### Restart a service
1. Stop the service
2. Wait 1 second
3. Start the service with correct configuration

### Restart hung Phoenix
Phoenix can sometimes hang (listen on port 4000 but not respond to requests):
1. Kill the Phoenix process: `kill $(lsof -ti:4000)`
2. Wait 2 seconds: `sleep 2`
3. Start Phoenix fresh with logging:
   ```bash
   cd ~/dev/superfly/ui-ex && \
   export OBAN_CRON=true && \
   export SSOKENIZER_URL="https://judgeless-pleasantly-tammera.ngrok-free.dev" && \
   export DATABASE_PORT=5432 && \
   export USAGE_DATABASE_PORT=6432 && \
   mix phx.server > /tmp/phoenix.log 2>&1 &
   ```
4. Wait 15 seconds for compilation
5. Verify it's responding: `curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:4000`
6. Check logs if needed: `tail -50 /tmp/phoenix.log`

### Status check
1. Check which services are running
2. Report port usage and process IDs
3. **For Phoenix**: Verify it's responding with HTTP 200 (not just listening)
4. Verify services are using correct configuration
5. Check logs at `/tmp/phoenix.log`, `/tmp/tokenizer.log`, `/tmp/ssokenizer.log` if issues found

## Important Notes

- **SEAL_KEY consistency**: The ssokenizer and tokenizer must use matching keypair
  - Tokenizer: Uses `OPEN_KEY`: `a29dcbaa824af8f0a8d435df6ca1f27cfbf1d5aaa03f3f87fa0a58f8a34d8f67`
  - Tokenizer derives seal_key: `6c8792058608dd8cfff94f689664bd25c073057c78b4c665b40fed52538b2867`
  - Ssokenizer: Configured in `dev-config.yml` with matching seal_key
  - Both are already configured correctly - no need to update manually
  - Tokenizer requires `NO_FLY_SRC=1` for local development (to skip fly-src parser which needs `/.fly/fly-src.pub`)

- **Process management**: Use `lsof -ti:<port>` to find processes by port, then `kill <pid>` to stop them

- **Background processes**: Run services in the background and log output to `/tmp/<service>.log`

- **Startup order**: For proper operation:
  1. Start fly-tools (web) first
  2. Start tokenizer and capture the seal_key from its output
  3. Start ngrok EARLY (before ssokenizer) - it needs to be running for OAuth to work
  4. Update ssokenizer dev-config.yml with the captured seal_key
  5. Start ssokenizer with updated configuration (requires ngrok to be running)
  6. Start ui-ex last with SSOKENIZER_URL pointing to ngrok URL

- **Ngrok requirement**: For Vanta OAuth integration:
  - Ngrok must be running before testing OAuth flows
  - The ngrok URL must be configured in Vanta's OAuth application settings
  - See `/docs/VANTA_OAUTH_ENDPOINTS.md` for how to configure Vanta endpoints

## Start All Services Procedure

When the user requests "start all services" or "refresh dev environment":

1. **Check Docker containers** (fly-tools databases)
   ```bash
   docker ps --filter "name=fly-tools"
   ```
   If not running, inform user to start with:
   ```bash
   cd ~/dev/superfly/fly-tools && ./run-with-web.sh -d
   ```

2. **Get database ports from Docker**
   ```bash
   docker ps --format "{{.Names}}: {{.Ports}}" | grep -E "(proxy_development-db|usage_development-db)"
   ```
   Extract the host ports for DATABASE_PORT and USAGE_DATABASE_PORT

3. **Start Ngrok** (BEFORE tokenizer - required for OAuth callbacks)
   ```bash
   ngrok http 3000 --domain=judgeless-pleasantly-tammera.ngrok-free.dev > /tmp/ngrok.log 2>&1 &
   ```
   Wait 3 seconds, then verify:
   ```bash
   sleep 3 && curl -s -o /dev/null -w "HTTP %{http_code}\n" https://judgeless-pleasantly-tammera.ngrok-free.dev/
   ```
   Expected: HTTP 404 (tunnel active, ssokenizer not running yet)

   **IMPORTANT**: Ngrok must be running for Vanta OAuth to work. See `/docs/VANTA_OAUTH_ENDPOINTS.md` for configuring Vanta's authorized endpoints.

4. **Start Tokenizer**
   First build the binary (once), then run it:
   ```bash
   cd /Users/mjbraun/dev/superfly/tokenizer && go build -o tokenizer ./cmd/tokenizer
   ```
   Then start:
   ```bash
   cd /Users/mjbraun/dev/superfly/tokenizer && \
   NO_FLY_SRC=1 \
   OPEN_KEY=a29dcbaa824af8f0a8d435df6ca1f27cfbf1d5aaa03f3f87fa0a58f8a34d8f67 \
   ./tokenizer > /tmp/tokenizer.log 2>&1 &
   ```
   Verify it started: `lsof -ti:8080`
   Check seal_key: `tail -5 /tmp/tokenizer.log | grep seal_key`
   Expected seal_key: `6c8792058608dd8cfff94f689664bd25c073057c78b4c665b40fed52538b2867`

   **Note**: `NO_FLY_SRC=1` is required for local development to skip fly-src parser initialization (which requires `/.fly/fly-src.pub` file)

5. **Start Ssokenizer**
   ```bash
   cd /Users/mjbraun/dev/superfly/ssokenizer && \
   export VANTA_CLIENT_ID=$(op read --account flyio "op://Employee/Vanta Test App/username") && \
   export VANTA_CLIENT_SECRET=$(op read --account flyio "op://Employee/Vanta Test App/credential") && \
   /opt/homebrew/bin/go run ./cmd/ssokenizer serve --config dev-config.yml > /tmp/ssokenizer.log 2>&1 &
   ```
   Verify it started: `lsof -ti:3000`

   **Note**: If `op read` fails, ensure you're authenticated: `op signin --account flyio`

6. **Start Phoenix (ui-ex)** - Choose one of two modes:

   **CRITICAL**: SSOKENIZER_URL MUST ALWAYS BE `https://judgeless-pleasantly-tammera.ngrok-free.dev` (NEVER use localhost)!
   If you use `http://localhost:3000`, OAuth will fail with "missing transaction cookie" error because the OAuth callback redirects through the ngrok public URL, causing cookie domain mismatch.

   **Option A: Normal mode (without proxy debugging)**
   ```bash
   cd /Users/mjbraun/dev/superfly/ui-ex && \
   export OBAN_CRON=true && \
   export SSOKENIZER_URL="https://judgeless-pleasantly-tammera.ngrok-free.dev" && \
   export DATABASE_PORT=<port_from_step_2> && \
   export USAGE_DATABASE_PORT=<port_from_step_2> && \
   export VANTA_CLIENT_ID=$(op read --account flyio "op://Employee/Vanta Test App/username") && \
   export VANTA_CLIENT_SECRET=$(op read --account flyio "op://Employee/Vanta Test App/credential") && \
   mix phx.server > /tmp/phoenix.log 2>&1 &
   ```

   **Option B: With intercepting proxy (for debugging OAuth/API requests)**
   ```bash
   cd /Users/mjbraun/dev/superfly/ui-ex && \
   export OBAN_CRON=true && \
   export HTTP_PROXY=http://localhost:8888 && \
   export HTTPS_PROXY=http://localhost:8888 && \
   export SSOKENIZER_URL="https://judgeless-pleasantly-tammera.ngrok-free.dev" && \
   export DATABASE_PORT=<port_from_step_2> && \
   export USAGE_DATABASE_PORT=<port_from_step_2> && \
   export VANTA_CLIENT_ID=$(op read --account flyio "op://Employee/Vanta Test App/username") && \
   export VANTA_CLIENT_SECRET=$(op read --account flyio "op://Employee/Vanta Test App/credential") && \
   mix phx.server > /tmp/phoenix.log 2>&1 &
   ```
   Note: Option B requires mitmproxy to be running first (see "Using Intercepting Proxy for Debugging" section)

   Wait 15-20 seconds for compilation, then verify: `lsof -ti:4000` or check for "Access FlyWeb.Endpoint at http://localhost:4000" in /tmp/phoenix.log

7. **Report status** of all services with their ports, PIDs, and ngrok public URL

## Database Setup for Fresh Containers

**IMPORTANT**: UI-EX shares databases with the web (Rails) project. The recommended way to set up databases is to use the web project's Docker setup, which handles schema creation and seeding automatically.

### Recommended: Use fly-tools/run-with-web.sh

This method sets up and seeds the databases using the web (Rails) project, which ui-ex then connects to:

1. **Remove any conflicting containers**
   ```bash
   docker ps -a | grep "development-db\|development-cache" | awk '{print $1}' | xargs docker rm -f
   ```

2. **Start fly-tools with web service**
   ```bash
   cd ~/dev/superfly/fly-tools && ./run-with-web.sh -d
   ```
   This will:
   - Create Docker containers for databases (proxy_development, usage_development)
   - Run Rails migrations to set up database schema
   - Seed the database with dev@fly.local user (password: 1q2w3e4r)
   - Start the web service on port 3001 (optional profile)

3. **Verify database was seeded**
   ```bash
   PGPASSWORD=postgres psql -h localhost -p 5432 -U postgres -d proxy_development -c "SELECT email FROM users WHERE email='dev@fly.local'"
   ```
   Should return: `dev@fly.local`

4. **Start ui-ex** (which will connect to the already-seeded databases)
   ```bash
   cd ~/dev/superfly/ui-ex
   export OBAN_CRON=true
   export SSOKENIZER_URL="https://judgeless-pleasantly-tammera.ngrok-free.dev"  # NEVER use localhost!
   export DATABASE_PORT=5432
   export USAGE_DATABASE_PORT=6432
   export VANTA_CLIENT_ID=$(op read --account flyio "op://Employee/Vanta Test App/username")
   export VANTA_CLIENT_SECRET=$(op read --account flyio "op://Employee/Vanta Test App/credential")
   mix phx.server > /tmp/phoenix.log 2>&1 &
   ```

**Login Credentials**: `dev@fly.local` / `1q2w3e4r`

**Note**: SSOKENIZER_URL must ALWAYS use the ngrok public URL, never localhost, or OAuth will fail!

### Alternative: UI-EX Only Setup (Not Recommended)

If you need to set up databases without the web project:

1. **Create databases**
   ```bash
   DATABASE_PORT=5432 USAGE_DATABASE_PORT=6432 mix ecto.create
   ```

2. **Load database schema from structure.sql**
   ```bash
   PGPASSWORD=postgres psql -h localhost -p 5432 -U postgres -d proxy_development < priv/repo/structure.sql
   PGPASSWORD=postgres psql -h localhost -p 6432 -U postgres -d usage_development < priv/usage_repo/structure.sql
   ```
   Note: Default credentials are username=postgres, password=postgres

3. **Run migrations** (for any migrations not in structure.sql)
   ```bash
   DATABASE_PORT=5432 USAGE_DATABASE_PORT=6432 mix ecto.migrate
   ```

4. **Seed database**
   ```bash
   DATABASE_PORT=5432 USAGE_DATABASE_PORT=6432 mix run priv/repo/seeds.exs
   ```

**Warning**: This method may have migration ordering issues. Use the fly-tools method above instead.

## Setting Up vanta-test Organization

After the database is seeded, create a test organization with Vanta features enabled:

1. **Create vanta-test organization with compliance package**
   ```bash
   cd ~/dev/superfly/ui-ex
   export DATABASE_PORT=5432
   export USAGE_DATABASE_PORT=6432
   mix run priv/scripts/setup_vanta_org_simple.exs
   ```

   Output:
   ```
   Creating vanta-test organization...
   Enabling compliance package...
   ✓ Compliance package enabled
   Adding dev@fly.local as admin member...
   ✓ Added dev@fly.local as admin
   ✓ vanta-test organization ready (slug: vanta-test, ID: 10)
   ```

2. **Verify the setup**
   ```bash
   # Check compliance package product audit
   PGPASSWORD=postgres psql -h localhost -p 5432 -U postgres -d proxy_development -c "SELECT id, product, state FROM product_audits WHERE organization_id = (SELECT id FROM organizations WHERE slug='vanta-test')"
   ```

   Expected output:
   ```
    id |           product           | state
   ----+-----------------------------+--------
     1 | compliance_package_standard | active
   ```

**How it works:**
- The script creates the vanta-test organization and adds dev@fly.local as admin
- Compliance package is enabled via `product_audits` table (bypasses Metronome for local dev)
- Feature flag `vanta-integration` uses LaunchDarkly SDK (disabled in dev, defaults to `true`)
- No manual feature flag setup needed - it automatically defaults to enabled in development

**Note**: This organization is used for testing Vanta OAuth integration and user syncing. Access at: http://localhost:4000/dashboard/vanta-test/compliance

## Verifying Services Status

After starting all services, verify they're running correctly:

**Check ngrok tunnel:**
```bash
curl -s http://localhost:4040/api/tunnels | python3 -m json.tool
```

Expected output should show:
```json
{
  "tunnels": [{
    "public_url": "https://judgeless-pleasantly-tammera.ngrok-free.dev",
    "config": {"addr": "http://localhost:3000"}
  }]
}
```

**Test ngrok endpoint accessibility:**
```bash
curl -I https://judgeless-pleasantly-tammera.ngrok-free.dev/health
```

Should return `HTTP/2 200`.

**If ngrok is offline:**
```bash
# Kill any existing ngrok processes
pkill -f "ngrok http"

# Restart ngrok with reserved domain
ngrok http 3000 --domain=judgeless-pleasantly-tammera.ngrok-free.dev > /tmp/ngrok.log 2>&1 &

# Verify it started
sleep 2 && curl -I https://judgeless-pleasantly-tammera.ngrok-free.dev/health
```

**Check other services:**
```bash
# ssokenizer
curl -I http://localhost:3000/health  # Should return 200

# tokenizer
ps aux | grep tokenizer | grep -v grep  # Should show running process

# Phoenix
curl -I http://localhost:4000  # Should return 200 or 302
```

## Using Intercepting Proxy for Debugging

When debugging OAuth flows or API requests, use mitmproxy:

1. **Start mitmproxy with custom logger**
   ```bash
   mitmdump --listen-port 8888 -s /tmp/mitmproxy_logger.py --set console_eventlog_verbosity=error > /dev/null 2>&1 &
   ```

2. **Start Phoenix with proxy environment variables**
   ```bash
   export OBAN_CRON=true && \
   export HTTP_PROXY=http://localhost:8888 && \
   export HTTPS_PROXY=http://localhost:8888 && \
   export DATABASE_PORT=5432 && \
   export USAGE_DATABASE_PORT=6432 && \
   export SSOKENIZER_URL="https://judgeless-pleasantly-tammera.ngrok-free.dev" && \
   mix phx.server > /tmp/phoenix.log 2>&1 &
   ```

   **Important:** Environment variables must be exported before running mix, not in the same command like `HTTP_PROXY=value mix phx.server` (that doesn't work in background mode).

3. **View captured traffic**
   ```bash
   python3 /tmp/show_proxy_flows.py
   ```

4. **SSL Certificate Verification**
   The Vanta client (`lib/fly/vanta/client.ex`) automatically disables SSL certificate verification when:
   - Running in dev mode (`Mix.env() == :dev`)
   - AND `HTTP_PROXY` environment variable is set

   This allows mitmproxy's self-signed certificate to be accepted in development while still validating certificates in production.

## Usage Examples

- "Start all services" - Follow the procedure above
- "Refresh dev environment" - Stop all and restart following the procedure
- "Restart tokenizer" - Kill port 8080 process and restart just tokenizer
- "Stop ssokenizer" - Kill port 3000 process
- "Check service status" - Check all service ports and report
- "Start ui-ex" - Just start Phoenix if other services are running
- "Set up fresh database" - Follow database setup procedure for fresh containers
