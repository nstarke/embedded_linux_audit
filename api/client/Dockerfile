FROM node:20-bookworm-slim

# `zip` streams the Haruspex decompiler output for GET /ghidra-analysis/:id/output.zip.
RUN apt-get update \
 && apt-get install -y --no-install-recommends zip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY api /app/api
COPY LICENSE.api /app/LICENSE.api

WORKDIR /app/api
RUN npm install --omit=dev

WORKDIR /app/api/client
RUN npm install --omit=dev

ENV NODE_ENV=production \
    ELA_CLIENT_HOST=0.0.0.0 \
    ELA_CLIENT_PORT=7000

EXPOSE 7000

CMD ["node", "/app/api/client/server.js"]
