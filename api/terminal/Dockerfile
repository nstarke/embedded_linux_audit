FROM node:20-bookworm-slim

WORKDIR /app

COPY api /app/api
COPY LICENSE.api /app/LICENSE.api

RUN apt-get update \
 && apt-get install -y --no-install-recommends tmux \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/api
RUN npm install --omit=dev

WORKDIR /app/api/terminal
RUN npm install --omit=dev

RUN chmod +x /app/api/terminal/entrypoint.sh

ENV NODE_ENV=production \
    ELA_TERMINAL_PORT=8080

EXPOSE 8080

CMD ["/app/api/terminal/entrypoint.sh"]
