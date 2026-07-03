# Debian slim (glibc) : better-sqlite3 y installe un binaire précompilé sans compilation.
FROM node:20-slim

# dumb-init : transmet correctement SIGTERM/SIGINT à Node (arrêt propre).
RUN apt-get update && apt-get install -y --no-install-recommends dumb-init \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Dossier de données (monté en volume par docker-compose) accessible à l'utilisateur node.
RUN mkdir -p /app/data && chown -R node:node /app/data

ENV NODE_ENV=production
EXPOSE 5050

USER node

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server/index.js"]
