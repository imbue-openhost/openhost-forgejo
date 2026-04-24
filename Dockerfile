FROM codeberg.org/forgejo/forgejo:14

# Runtime additions on top of the upstream Forgejo image:
#
#   python3 + py3-pip  — runtime for the auth-proxy sidecar (auth_proxy.py)
#                        and pip (used to install PyJWT + requests via venv)
#   bash               — start.sh uses `wait -n`, which is bash-only
#                        (busybox ash, Alpine's default /bin/sh, lacks it)
RUN apk add --no-cache python3 py3-pip bash

# Install PyJWT (with the cryptography extra for RS256) and requests
# inside a venv, isolated from the system Python so we don't need
# --break-system-packages on Alpine 3.20+. Versions are pinned for
# reproducible builds; bump intentionally when needed.
RUN python3 -m venv /opt/auth-venv \
 && /opt/auth-venv/bin/pip install --no-cache-dir \
        'PyJWT[crypto]==2.9.0' \
        'requests==2.32.3'

# Copy our startup wrapper and the auth proxy.
COPY start.sh /app/start.sh
COPY auth_proxy.py /app/auth_proxy.py
RUN chmod +x /app/start.sh

EXPOSE 3000

ENTRYPOINT []
CMD ["/app/start.sh"]
