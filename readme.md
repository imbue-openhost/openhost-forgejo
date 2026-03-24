Forgejo self-hosted Git forge for OpenHost. Runs as a single Docker container:

- Forgejo v14 (Git hosting, code review, issue tracking, CI/CD via Actions)
- SQLite (no external database required)
- Persistent data in OpenHost's app_data directory

## How it works

On first boot, the container:
1. Creates data directories in the OpenHost persistent storage
2. Generates and persists a secret key
3. Configures Forgejo with the correct domain derived from OpenHost environment variables
4. Starts Forgejo with install lock enabled (no manual setup wizard)

Registration is open by default. The first user to register becomes the admin.

## Deploying

Deploy via the OpenHost router dashboard — point it at this repo. The app will be available at `{app_name}.{zone_domain}` via subdomain routing (e.g. `forgejo.zack.host.imbue.com`).

## Data

All persistent data lives in `$OPENHOST_APP_DATA_DIR/forgejo/`:
- `gitea/forgejo.db` — SQLite database (users, repos, issues, etc.)
- `gitea/conf/` — Forgejo configuration
- `git/repositories/` — bare Git repositories
- `gitea/avatars/`, `gitea/attachments/`, etc.

## Resources

Needs ~512MB RAM and 0.5 CPU cores. The container image is ~300MB.

## Configuration

`start.sh` auto-configures Forgejo via environment variables at runtime. Key settings:
- Domain and ROOT_URL derived from `OPENHOST_ZONE_DOMAIN` and `OPENHOST_APP_NAME`
- SQLite database (no external DB needed)
- SSH disabled (Git over HTTPS only, routed through OpenHost)
- Install lock enabled (skips setup wizard)

## Files

- `Dockerfile` — extends the official Forgejo v14 image
- `start.sh` — configures Forgejo via env vars and launches it
- `openhost.toml` — OpenHost app manifest
