FROM codeberg.org/forgejo/forgejo:14

# Runtime additions on top of the upstream Forgejo image:
#
#   python3  — runtime for the auth-proxy sidecar (auth_proxy.py);
#              uses only stdlib modules (http.client, http.server)
#   bash     — start.sh uses `wait -n`, which is bash-only
#              (busybox ash, Alpine's default /bin/sh, lacks it)
RUN apk add --no-cache python3 bash

# Copy our startup wrapper and the auth proxy.
COPY start.sh /app/start.sh
COPY auth_proxy.py /app/auth_proxy.py
RUN chmod +x /app/start.sh

EXPOSE 3000

ENTRYPOINT []
CMD ["/app/start.sh"]
