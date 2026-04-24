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
5. Bootstraps an `admin` account with a random password and writes the credentials to `$OPENHOST_APP_DATA_DIR/admin-password.txt`

Public signups are **disabled** by design. The admin adds other users from the Site Administration panel (see "Adding users" below).

## Deploying

Deploy via the OpenHost router dashboard — point it at this repo. The app will be available at `{app_name}.{zone_domain}` via subdomain routing (e.g. `forgejo.zack.host.imbue.com`).

## First login

Once the container is running, grab the admin password from inside the data dir. On the host:

```
sudo cat /home/host/.openhost/local_compute_space/persistent_data/app_data/forgejo/admin-password.txt
```

Or use the OpenHost file-browser app. Log in as `admin` with the password, go to your user settings, change it to something you'll remember, and delete the file.

To customise the bootstrap username or email, set these env vars before first boot (the OpenHost way is via the app's environment config):

- `FORGEJO_ADMIN_USERNAME` (default: `admin`)
- `FORGEJO_ADMIN_EMAIL` (default: `admin@{domain}`)

Once the bootstrap runs, a sentinel file (`.admin_bootstrapped`) is written to prevent re-bootstrap. Changing the env vars afterwards has no effect.

## Adding users

Walk-in signups at `/user/sign_up` return 403 by design. To add users:

1. Log in as admin.
2. Go to **Site Administration → User Accounts → Create User Account**.
3. Either:
   - **Set a password directly** for the new user and hand it to them over a secure channel. They can change it at first login.
   - **Send activation email** (requires SMTP — not configured in this wrapper by default). The recipient gets a one-time activation link and sets their own password.

If SMTP isn't configured, an equivalent manual flow is:

1. Create the user with a temporary password.
2. Hand them the URL + temp password out of band.
3. They log in, change the password in their settings.

For per-repository collaborators, the owner can also add users by email from the repo's **Settings → Collaborators** page — Forgejo will send an invite (again, requires SMTP for email delivery).

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
