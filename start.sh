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
fi

# Derive domain from OpenHost environment
if [ -n "$OPENHOST_ZONE_DOMAIN" ]; then
    APP_SUBDOMAIN="${OPENHOST_APP_NAME:-forgejo}"
    DOMAIN_NAME="${APP_SUBDOMAIN}.${OPENHOST_ZONE_DOMAIN}"
    ROOT_URL="https://${DOMAIN_NAME}/"
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
export FORGEJO__server__HTTP_PORT="3000"
export FORGEJO__server__HTTP_ADDR="0.0.0.0"
export FORGEJO__server__DISABLE_SSH="true"

export FORGEJO__database__DB_TYPE="sqlite3"

export FORGEJO__security__SECRET_KEY="$SECRET_KEY"
export FORGEJO__security__INSTALL_LOCK="true"

export FORGEJO__service__DISABLE_REGISTRATION="false"
export FORGEJO__service__REQUIRE_SIGNIN_VIEW="false"

export FORGEJO__log__LEVEL="Info"

# Hand off to the official entrypoint (handles user setup, s6, etc.)
exec /usr/bin/entrypoint
