FROM codeberg.org/forgejo/forgejo:14

# Install Caddy for Host header rewriting (the OpenHost router strips Host
# and sets X-Forwarded-Host; Forgejo's CSRF check needs them to match)
RUN apk add --no-cache caddy

# Copy our startup wrapper and Caddyfile
COPY start.sh /app/start.sh
COPY Caddyfile /app/Caddyfile
RUN chmod +x /app/start.sh

EXPOSE 3000

ENTRYPOINT []
CMD ["/app/start.sh"]
