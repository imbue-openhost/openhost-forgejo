FROM codeberg.org/forgejo/forgejo:14

# Copy our startup wrapper
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 3000

ENTRYPOINT []
CMD ["/app/start.sh"]
