FROM node:20-bookworm-slim

WORKDIR /app

COPY api /app/api
COPY LICENSE.api /app/LICENSE.api

WORKDIR /app/api
RUN npm install --omit=dev

WORKDIR /app/api/gdb
RUN npm install --omit=dev

ENV NODE_ENV=production \
    ELA_GDB_HOST=0.0.0.0 \
    ELA_GDB_PORT=9000

EXPOSE 9000

CMD ["node", "/app/api/gdb/server.js"]
