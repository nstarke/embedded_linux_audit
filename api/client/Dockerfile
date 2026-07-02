FROM node:20-bookworm-slim

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
