Forgejo self-hosted Git forge for OpenHost. Single Docker container, with
two authentication paths:

- **Owner**: silently logged in as Forgejo admin (`operator` user) via OpenHost SSO. No password to manage, no login form to fill in.
- **Invited users**: log in with a Forgejo-local password. The admin creates their account from Site Administration → User Accounts → Create Account.

Walk-in registrations at `/user/sign_up` are disabled. Public repos remain
browsable without login (`REQUIRE_SIGNIN_VIEW=false`).

## How the auth flows work

The container runs two processes side by side:

1. **`auth_proxy.py`** binds the public port (3000) and is what the OpenHost router talks to. When the router stamps `X-OpenHost-Is-Owner: true` on the request (meaning the visitor holds a valid session), the proxy adds an `X-Openhost-User: operator` header on the upstream request to Forgejo. It also rewrites the `Host` header from `X-Forwarded-Host` so Forgejo's CSRF check sees the right origin.

2. **Forgejo** itself binds 127.0.0.1:3001 (loopback only, not reachable from outside the container). It's configured with `ENABLE_REVERSE_PROXY_AUTHENTICATION = true` + `REVERSE_PROXY_AUTHENTICATION_USER = X-Openhost-User`, so a stamped header is treated as a logged-in session. `ENABLE_REVERSE_PROXY_AUTO_REGISTRATION = true` means the `operator` user is auto-created on the first owner request — that user gets ID 1, which Forgejo treats as admin.

`REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.1/32` means Forgejo only honors the header when it comes from the auth-proxy on loopback. The auth-proxy strips any inbound `X-Openhost-User` and `X-OpenHost-Is-Owner` headers before forwarding, as defence in depth. The router itself strips all client-supplied `X-OpenHost-*` headers before forwarding to apps, so the `X-OpenHost-Is-Owner` header is unforgeable.

Non-owner visitors (no `X-OpenHost-Is-Owner` header) get the request passed through unchanged. Forgejo sees no auth-proxy header and falls through to its normal session/password flow — invited users log in at `/user/login` like on any vanilla forge.

## Deploying

Deploy via the OpenHost router dashboard — point it at this repo. The app will be available at `{app_name}.{zone_domain}` (e.g. `forgejo.zack.host.imbue.com`).

First request from the OpenHost owner triggers the admin-account auto-creation. No password file is generated; there's nothing to copy out of the container.

## Adding users

Walk-in `POST /user/sign_up` returns 403 by design. To add users:

1. Visit `forgejo.zone` as the OpenHost owner. You'll be silently logged in as `operator` with admin rights.
2. Go to **Site Administration → User Accounts → Create User Account**.
3. Either:
   - **Set a password directly** for the new user and hand it to them over a secure channel (Slack, Signal, etc.). They can change it on first login under their user settings.
   - **Send activation email** (requires SMTP — not configured by this wrapper). The recipient gets a one-time activation link and sets their own password.

If SMTP isn't configured, the manual flow is:

1. Create the user with a temporary password.
2. Hand them the URL + temp password out of band.
3. They log in at `https://forgejo.zone/user/login` and change the password in their settings.

For per-repository collaborators, the owner can also add users by email from the repo's **Settings → Collaborators** page (also requires SMTP for email delivery).

## Caveats

- **Forgejo reserves `admin`.** That's why the owner is mapped to `operator`, not `admin`. Both behave identically (user ID 1 is always admin in Forgejo). The username is hardcoded in `auth_proxy.py`.
- **One OpenHost owner = one Forgejo admin user.** If you want multiple admins, log in via SSO once to auto-create `operator`, then promote other Forgejo accounts to admin via Site Administration → Users → Edit → "Set as administrator".
- **No SMTP.** Forgejo's built-in email features (activation links, password reset, repo collab invites) need SMTP configured separately. Without it you fall back to manual password handoffs.
- **No SSH.** `DISABLE_SSH = true`, so git operations go over HTTPS only. Authenticate with personal access tokens rather than SSH keys (Settings → Applications → Generate New Token).

## Data

All persistent data lives in `$OPENHOST_APP_DATA_DIR/forgejo/`:

```
$OPENHOST_APP_DATA_DIR/forgejo/
├── gitea/
│   ├── forgejo.db              # SQLite: users, repos, issues, etc.
│   ├── conf/app.ini            # Forgejo's effective config
│   ├── attachments/, avatars/, …
├── git/
│   └── repositories/           # bare git repos
├── ssh/                        # (unused; SSH disabled)
└── .secret_key                 # generated on first boot, persisted
```

## Files

- `Dockerfile` — extends the official Forgejo v14 image with python3 + bash for the auth-proxy.
- `start.sh` — sets the env-var config and starts both auth-proxy and Forgejo.
- `auth_proxy.py` — the SSO sidecar. Reads the router's `X-OpenHost-Is-Owner` header, stamps `X-Openhost-User: operator` for the owner, otherwise passes through unchanged. Also rewrites Host from X-Forwarded-Host.
- `openhost.toml` — OpenHost manifest. `public_paths = ["/"]` so invited users can reach the login form; `health_check = "/api/healthz"` for router liveness probes.
