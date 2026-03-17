FROM node:20-bookworm-slim

WORKDIR /app

COPY api /app/api
COPY tests /app/tests
COPY tools /app/tools
COPY Makefile /app/Makefile
COPY README.md /app/README.md
COPY LICENSE.api /app/LICENSE.api

WORKDIR /app/api
RUN npm install --omit=dev

WORKDIR /app/api/agent
RUN npm install --omit=dev

ENV NODE_ENV=production \
    ELA_AGENT_HOST=0.0.0.0 \
    ELA_AGENT_PORT=5000 \
    ELA_AGENT_SKIP_ASSET_SYNC=true

EXPOSE 5000

CMD ["node", "server.js", "--reuse-last-data-dir"]
