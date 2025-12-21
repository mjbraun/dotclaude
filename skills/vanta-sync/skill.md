# Vanta Sync Skill

Manually trigger a Vanta user sync for an organization.

## Usage

This skill triggers an immediate Vanta user sync job through Oban.

## Parameters

- `org_slug` (optional): Organization slug to sync (defaults to "vanta-test")

## What it does

1. Looks up the organization by slug
2. Inserts a VantaUserSyncWorker job into Oban
3. The job runs immediately and syncs users to Vanta
4. Reports the sync result
