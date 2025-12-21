#!/bin/bash
set -e

# Default to vanta-test if no org slug provided
ORG_SLUG="${1:-vanta-test}"

echo "Triggering Vanta sync for organization: $ORG_SLUG"

cd /Users/mjbraun/dev/superfly/ui-ex

# Get the org ID from the database
ORG_ID=$(docker exec proxy_development-db psql -U postgres -d proxy_development -t -c "SELECT id FROM organizations WHERE slug = '$ORG_SLUG' AND vanta_linked = true;" | xargs)

if [ -z "$ORG_ID" ]; then
    echo "Error: Organization '$ORG_SLUG' not found or not linked to Vanta"
    exit 1
fi

echo "Found organization ID: $ORG_ID"

# Insert Oban job directly into the oban_development database
docker exec proxy_development-db psql -U postgres -d oban_development -c "INSERT INTO oban_jobs (state, queue, worker, args) VALUES ('available', 'scheduled', 'Fly.Workers.VantaUserSyncWorker', '{\"organization_id\": $ORG_ID}'::jsonb);"

echo "✓ Vanta sync job queued successfully"
echo "Check Phoenix logs for [Vanta] messages to see sync progress"
echo "Or visit http://localhost:4000/oban to monitor the job"
