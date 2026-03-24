#!/bin/sh
set -e

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/data}"
FORGEJO_DATA="$DATA_DIR/forgejo"

# Ensure data directories exist
mkdir -p "$FORGEJO_DATA" "$FORGEJO_DATA/gitea" "$FORGEJO_DATA/gitea/conf"

# Derive domain from OpenHost environment
if [ -n "$OPENHOST_ZONE_DOMAIN" ]; then
    APP_SUBDOMAIN="${OPENHOST_APP_NAME:-forgejo}"
    DOMAIN_NAME="${APP_SUBDOMAIN}.${OPENHOST_ZONE_DOMAIN}"
    ROOT_URL="https://${DOMAIN_NAME}/"
else
    DOMAIN_NAME="${DOMAIN_NAME:-localhost}"
    ROOT_URL="http://${DOMAIN_NAME}:3000/"
fi

# Generate a secret key if not already persisted
SECRET_KEY_FILE="$FORGEJO_DATA/.secret_key"
if [ -f "$SECRET_KEY_FILE" ]; then
    SECRET_KEY=$(cat "$SECRET_KEY_FILE")
else
    SECRET_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | head -c 40)
    echo -n "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

# Configure Forgejo via environment variables
# See: https://forgejo.org/docs/latest/admin/config-cheat-sheet/
export FORGEJO__DEFAULT__APP_NAME="Forgejo"
export FORGEJO__server__DOMAIN="$DOMAIN_NAME"
export FORGEJO__server__ROOT_URL="$ROOT_URL"
export FORGEJO__server__HTTP_PORT="3000"
export FORGEJO__server__HTTP_ADDR="0.0.0.0"
export FORGEJO__server__SSH_DOMAIN="$DOMAIN_NAME"
export FORGEJO__server__DISABLE_SSH="true"

export FORGEJO__database__DB_TYPE="sqlite3"
export FORGEJO__database__PATH="$FORGEJO_DATA/gitea/forgejo.db"

export FORGEJO__security__SECRET_KEY="$SECRET_KEY"
export FORGEJO__security__INSTALL_LOCK="true"

export FORGEJO__service__DISABLE_REGISTRATION="false"
export FORGEJO__service__REQUIRE_SIGNIN_VIEW="false"

export FORGEJO__log__LEVEL="Info"

# Map Forgejo data to our persistent directory
export GITEA_WORK_DIR="$FORGEJO_DATA"
export GITEA_CUSTOM="$FORGEJO_DATA/gitea"

# Run the official Forgejo entrypoint
exec /usr/bin/entrypoint
