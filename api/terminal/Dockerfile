FROM node:20-bookworm-slim

WORKDIR /app

COPY api /app/api
COPY LICENSE.api /app/LICENSE.api

WORKDIR /app/api
RUN npm install --omit=dev

WORKDIR /app/api/terminal
RUN npm install --omit=dev

ENV NODE_ENV=production \
    ELA_TERMINAL_PORT=8080

EXPOSE 8080

CMD ["node", "server.js"]
