#!/bin/sh
set -e

# OpenHost mounts persistent storage at OPENHOST_APP_DATA_DIR.
# The Forgejo image expects all data under /data/ (gitea, git, ssh dirs).
# We symlink the key directories so Forgejo's defaults persist correctly.
PERSIST="${OPENHOST_APP_DATA_DIR:-/data}"

if [ "$PERSIST" != "/data" ]; then
    # Move Forgejo's data roots into the persistent directory
    for dir in gitea git ssh; do
        target="$PERSIST/$dir"
        link="/data/$dir"
        mkdir -p "$target"
        # Remove the default dir (or stale symlink) and replace with symlink
        rm -rf "$link"
        ln -sf "$target" "$link"
    done
    # The entrypoint's chown on symlinks doesn't reach the targets,
    # so we must fix ownership on the actual persistent directories.
    chown -R git:git "$PERSIST"
fi

# Derive domain and ROOT_URL from OpenHost environment.
# In production, the router terminates TLS and the app is at https://<subdomain>.<zone>.
# In dev (lvh.me), there's no TLS and the router exposes on a non-standard port.
if [ -n "$OPENHOST_ZONE_DOMAIN" ]; then
    APP_SUBDOMAIN="${OPENHOST_APP_NAME:-forgejo}"
    DOMAIN_NAME="${APP_SUBDOMAIN}.${OPENHOST_ZONE_DOMAIN}"

    case "$OPENHOST_ZONE_DOMAIN" in
        lvh.me|*.lvh.me|localhost|*.localhost)
            # Dev environment — use http with the router's external port
            ROUTER_PORT=""
            if [ -n "$OPENHOST_ROUTER_URL" ]; then
                ROUTER_PORT=$(echo "$OPENHOST_ROUTER_URL" | sed -n 's/.*:\([0-9]*\)$/\1/p')
            fi
            ROOT_URL="http://${DOMAIN_NAME}${ROUTER_PORT:+:$ROUTER_PORT}/"
            ;;
        *)
            # Production — HTTPS on standard port
            ROOT_URL="https://${DOMAIN_NAME}/"
            ;;
    esac
else
    DOMAIN_NAME="${DOMAIN_NAME:-localhost}"
    ROOT_URL="http://${DOMAIN_NAME}:3000/"
fi

# Generate and persist a secret key across restarts
SECRET_KEY_FILE="$PERSIST/.secret_key"
if [ -f "$SECRET_KEY_FILE" ]; then
    SECRET_KEY=$(cat "$SECRET_KEY_FILE")
else
    SECRET_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | head -c 40)
    echo -n "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

# Configure Forgejo via environment variables (applied by environment-to-ini)
# See: https://forgejo.org/docs/latest/admin/config-cheat-sheet/
export FORGEJO__DEFAULT__APP_NAME="Forgejo"
export FORGEJO__server__DOMAIN="$DOMAIN_NAME"
export FORGEJO__server__ROOT_URL="$ROOT_URL"
# Forgejo listens on 3001 internally; Caddy on 3000 rewrites the Host
# header from X-Forwarded-Host so Forgejo's CSRF check passes.
export FORGEJO__server__HTTP_PORT="3001"
export FORGEJO__server__HTTP_ADDR="0.0.0.0"
export FORGEJO__server__DISABLE_SSH="true"

export FORGEJO__database__DB_TYPE="sqlite3"

export FORGEJO__security__SECRET_KEY="$SECRET_KEY"
export FORGEJO__security__INSTALL_LOCK="true"

# Registration policy: closed by default.
#
# Walk-ins cannot sign themselves up — the public "/user/sign_up"
# endpoint returns 403. New accounts come from the admin via the
# Site Administration panel: either by creating the user directly
# (the admin sets a password and hands it off), or by generating
# a one-time activation / invite link that the recipient uses to
# set their own password.
#
# Note: Forgejo has no "first user sees registration anyway" bypass
# — if DISABLE_REGISTRATION is true, even the initial admin can't
# self-register through the web. We bootstrap the admin out-of-band
# below via ``gitea admin user create`` on first boot.
export FORGEJO__service__DISABLE_REGISTRATION="true"
export FORGEJO__service__REQUIRE_SIGNIN_VIEW="false"

export FORGEJO__log__LEVEL="Info"

# -------------------------------------------------------------------
# Bootstrap the admin account on first boot.
#
# Detects "first boot" by the absence of the admin-bootstrap
# sentinel file. On first boot we run ``gitea migrate`` (applies
# the schema without starting the web server) followed by
# ``gitea admin user create`` (creates the admin row directly in
# sqlite), then stash the generated password at
# $PERSIST/admin-password.txt for the operator.
#
# The canonical ``admin`` username is a reserved word in Forgejo's
# username list, so the default here is ``operator``. Override via
# FORGEJO_ADMIN_USERNAME if you want something else.
# -------------------------------------------------------------------
ADMIN_BOOTSTRAP_SENTINEL="$PERSIST/.admin_bootstrapped"
ADMIN_PASSWORD_FILE="$PERSIST/admin-password.txt"
ADMIN_USERNAME="${FORGEJO_ADMIN_USERNAME:-operator}"
ADMIN_EMAIL="${FORGEJO_ADMIN_EMAIL:-admin@${DOMAIN_NAME}}"

if [ ! -f "$ADMIN_BOOTSTRAP_SENTINEL" ]; then
    echo "[openhost-forgejo] first boot — bootstrapping admin user '$ADMIN_USERNAME'" >&2

    ADMIN_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | head -c 24)
    if [ -z "$ADMIN_PASSWORD" ]; then
        echo "[openhost-forgejo] FATAL: could not generate admin password" >&2
        exit 1
    fi

    # Apply the schema + create the user as the forgejo runtime
    # user ('git') so file paths and ownership match what the
    # official entrypoint later expects. Both commands are
    # idempotent-ish on re-run (migrate no-ops if up-to-date;
    # user create errors if the name exists), but we only run
    # them when the sentinel is absent.
    BOOTSTRAP_LOG="$PERSIST/admin-bootstrap.log"
    : > "$BOOTSTRAP_LOG"
    bootstrap_ok=0
    if su git -s /bin/sh -c "gitea migrate" \
        >>"$BOOTSTRAP_LOG" 2>&1 \
        && su git -s /bin/sh -c "gitea admin user create \
            --username '$ADMIN_USERNAME' \
            --email '$ADMIN_EMAIL' \
            --password '$ADMIN_PASSWORD' \
            --admin \
            --must-change-password=false" \
            >>"$BOOTSTRAP_LOG" 2>&1; then
        bootstrap_ok=1
    fi

    if [ "$bootstrap_ok" = "1" ]; then
        umask 077
        cat > "$ADMIN_PASSWORD_FILE" <<EOF
Forgejo admin credentials
-------------------------
URL:      $ROOT_URL
Username: $ADMIN_USERNAME
Password: $ADMIN_PASSWORD

This file was generated on first boot and is NOT regenerated. Log
in, change the password via the user settings page, then delete
this file. If you lose the password, reset it from inside the
container with:

    su git -c "gitea admin user change-password --username '$ADMIN_USERNAME' --password NEW_PASSWORD"

To invite additional users, log in as the operator account and go to:
    Site Administration -> User Accounts -> Create Account
Forgejo can either set an initial password for the new user (which
you hand to them) or email them an activation link (if SMTP is
configured in app.ini). Walk-in signups at /user/sign_up are
disabled by design.
EOF
        chmod 600 "$ADMIN_PASSWORD_FILE"
        umask 022
        touch "$ADMIN_BOOTSTRAP_SENTINEL"
        echo "[openhost-forgejo] admin created; credentials at $ADMIN_PASSWORD_FILE" >&2
    else
        echo "[openhost-forgejo] WARNING: admin bootstrap failed — see $BOOTSTRAP_LOG" >&2
        # Don't create the sentinel; next boot will retry.
    fi
fi

# Start Caddy in background — it rewrites Host from X-Forwarded-Host on
# port 3000, then proxies to Forgejo on port 3001.
caddy run --config /app/Caddyfile &

# Hand off to the official entrypoint (handles user setup, s6, etc.)
exec /usr/bin/entrypoint
