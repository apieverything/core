FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

ENV PORT=9000 \
    HOST=0.0.0.0 \
    NODE_ENV=production \
    CORE_DATA_DIR=/app/.data

VOLUME ["/app/.data"]
EXPOSE 9000

CMD ["node", "server.js"]
