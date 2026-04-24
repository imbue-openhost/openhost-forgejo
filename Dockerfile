FROM codeberg.org/forgejo/forgejo:14

# Runtime additions on top of the upstream Forgejo image:
#
#   python3            — runtime for the auth-proxy sidecar (auth_proxy.py)
#   py3-pyjwt          — RS256 verification of the OpenHost zone_auth cookie
#   py3-requests       — JWKS fetch (with stale-fallback) from the router
#   py3-cryptography   — PyJWT's backend for RS256
#   bash               — start.sh uses `wait -n`, which is bash-only
#                        (busybox ash, Alpine's default /bin/sh, lacks it)
RUN apk add --no-cache python3 py3-pyjwt py3-requests py3-cryptography bash

# Copy our startup wrapper and the auth proxy.
COPY start.sh /app/start.sh
COPY auth_proxy.py /app/auth_proxy.py
RUN chmod +x /app/start.sh

EXPOSE 3000

ENTRYPOINT []
CMD ["/app/start.sh"]
