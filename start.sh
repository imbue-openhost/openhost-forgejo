#!/bin/bash
# Bash specifically (not /bin/sh): we use `wait -n`, which busybox
# ash (Alpine's default /bin/sh) doesn't implement. The Forgejo
# Dockerfile installs bash for us.
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

# Per-deployment env overrides.  OpenHost has no per-app env-var API;
# this is the workaround pattern: drop a file at $PERSIST/openhost.env
# and we source it on every boot.  Lines are KEY=value (shell
# syntax).  Used today for OPENHOST_HAIRPIN_HOSTS; can hold any
# Forgejo or app-level env vars going forward.
if [ -f "$PERSIST/openhost.env" ]; then
    echo "[start.sh] sourcing $PERSIST/openhost.env"
    set -a
    # shellcheck disable=SC1091
    . "$PERSIST/openhost.env"
    set +a
fi

# Hairpin workaround.  Outbound HTTP from this container to a sibling
# OpenHost app on the same zone (typical case: webhooks targeting
# https://drone.<zone>) tries to dial the host's public IP, but
# rootless podman + slirp4netns won't NAT-loop the packet back to
# the same host's Caddy.  Symptom: webhook deliveries fail with
# 'connection refused' or time out.
#
# Fix: pin sibling-app hostnames to host.containers.internal in
# /etc/hosts.  The operator opts in by setting OPENHOST_HAIRPIN_HOSTS
# to a comma- or space-separated list of FQDNs (e.g.
# 'drone.andrew-1.selfhost.imbue.com').  Caddy listens on
# 0.0.0.0:443 so it answers on the gateway IP too; TLS validates
# fine because the request hostname is unchanged.
if [ -n "${OPENHOST_HAIRPIN_HOSTS:-}" ]; then
    GATEWAY_IP=$(getent hosts host.containers.internal 2>/dev/null | awk '{print $1}' | head -1)
    if [ -n "$GATEWAY_IP" ]; then
        for HOST in $(echo "$OPENHOST_HAIRPIN_HOSTS" | tr ',' ' '); do
            [ -z "$HOST" ] && continue
            if ! grep -qF " $HOST" /etc/hosts; then
                echo "$GATEWAY_IP $HOST" >> /etc/hosts
                echo "[start.sh] pinned $HOST to $GATEWAY_IP in /etc/hosts (hairpin workaround)"
            fi
        done
    else
        echo "[start.sh] WARNING: OPENHOST_HAIRPIN_HOSTS set but host.containers.internal did not resolve" >&2
    fi
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

# ---------------------------------------------------------------------------
# Forgejo configuration via env vars (consumed by environment-to-ini).
# See: https://forgejo.org/docs/latest/admin/config-cheat-sheet/
# ---------------------------------------------------------------------------
export FORGEJO__DEFAULT__APP_NAME="Forgejo"
export FORGEJO__server__DOMAIN="$DOMAIN_NAME"
export FORGEJO__server__ROOT_URL="$ROOT_URL"
# Forgejo listens on 3001 internally. The Python auth_proxy.py
# sidecar (started below) is what binds 0.0.0.0:3000, terminating
# the OpenHost router's connection and forwarding to Forgejo with
# (a) Host rewritten from X-Forwarded-Host (so CSRF passes) and
# (b) X-Openhost-User stamped if the visitor is the OpenHost owner.
export FORGEJO__server__HTTP_PORT="3001"
export FORGEJO__server__HTTP_ADDR="127.0.0.1"
export FORGEJO__server__DISABLE_SSH="true"

export FORGEJO__database__DB_TYPE="sqlite3"

export FORGEJO__security__SECRET_KEY="$SECRET_KEY"
export FORGEJO__security__INSTALL_LOCK="true"
# Trust only the auth-proxy sidecar (running on loopback inside the
# same container) to set X-Openhost-User. Anyone else's header
# claim is ignored — Forgejo treats the request as anonymous.
export FORGEJO__security__REVERSE_PROXY_TRUSTED_PROXIES="127.0.0.1/32"
export FORGEJO__security__REVERSE_PROXY_AUTHENTICATION_USER="X-Openhost-User"

# Walk-in registrations at /user/sign_up are blocked: visitors who
# don't already hold an account can't make one without an admin
# explicitly creating it. Reverse-proxy auto-registration is on,
# but that path only fires for requests carrying a valid (signed)
# X-Openhost-User header — i.e. the OpenHost owner.
export FORGEJO__service__DISABLE_REGISTRATION="true"
export FORGEJO__service__REQUIRE_SIGNIN_VIEW="false"
export FORGEJO__service__ENABLE_REVERSE_PROXY_AUTHENTICATION="true"
export FORGEJO__service__ENABLE_REVERSE_PROXY_AUTO_REGISTRATION="true"

export FORGEJO__log__LEVEL="Info"

# Webhook delivery allow-list.  Forgejo's default ALLOWED_HOST_LIST
# is 'external' which blocks RFC1918 / loopback targets.  Sibling
# OpenHost apps on the same zone are reached via the hairpin
# workaround above (host.containers.internal, in 172.16.0.0/12),
# so by default Forgejo refuses to deliver webhooks to them with
# 'webhook can only call allowed HTTP servers'.
#
# We allow:
#   * '*.${OPENHOST_ZONE_DOMAIN}' so any sibling app on this zone
#     is reachable as a webhook target.
#   * 'private' (RFC1918 ranges) so the hairpin gateway IP itself
#     is allowed once /etc/hosts pins resolve there.
#   * 'external' to preserve the default allow for public IPs.
# Operators can override by exporting FORGEJO__webhook__ALLOWED_HOST_LIST
# from $PERSIST/openhost.env before this point — the export below
# is a no-op if the variable is already set in the environment.
if [ -z "${FORGEJO__webhook__ALLOWED_HOST_LIST:-}" ]; then
    if [ -n "$OPENHOST_ZONE_DOMAIN" ]; then
        export FORGEJO__webhook__ALLOWED_HOST_LIST="*.${OPENHOST_ZONE_DOMAIN},private,external"
    else
        export FORGEJO__webhook__ALLOWED_HOST_LIST="private,external"
    fi
fi

# ---------------------------------------------------------------------------
# Start the auth-proxy sidecar.
# The proxy verifies the visitor's `zone_auth` JWT cookie against the
# OpenHost router's JWKS and, on `sub == "owner"`, stamps
# `X-Openhost-User: operator` on the upstream request to Forgejo.
# Forgejo, configured above, treats that as an authenticated session
# for the `operator` user. Non-owner traffic falls through to
# Forgejo's normal session/password auth.
# ---------------------------------------------------------------------------
# Use the venv-installed python so PyJWT + requests are on the path.
/opt/auth-venv/bin/python /app/auth_proxy.py &
AUTH_PROXY_PID=$!

# Hand off to the official entrypoint (handles s6 startup,
# environment-to-ini, the gitea web server) as a sibling background
# process. If either dies, the wait/trap logic below tears the
# container down so OpenHost notices and restarts us.
/usr/bin/entrypoint &
ENTRYPOINT_PID=$!

# Forward SIGTERM/SIGINT to BOTH children so a `docker stop` /
# OpenHost stop signal lets Forgejo's s6 supervisor flush the DB
# cleanly instead of leaving the proxy running by itself.
trap 'kill -TERM "$AUTH_PROXY_PID" "$ENTRYPOINT_PID" 2>/dev/null; wait' TERM INT

# Block until either child exits, then tear down the survivor.
# `wait -n` is a bash builtin and returns as soon as any
# backgrounded job exits. Disable errexit around it because a
# non-zero child exit (or signal-driven exit) would otherwise
# abort the script before the explicit cleanup runs.
set +e
wait -n "$AUTH_PROXY_PID" "$ENTRYPOINT_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] child exited (code=$EXIT_CODE); shutting down" >&2
kill -TERM "$AUTH_PROXY_PID" "$ENTRYPOINT_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
