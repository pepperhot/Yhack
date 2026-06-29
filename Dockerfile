FROM node:20-alpine

# dumb-init : transmet correctement SIGTERM/SIGINT à Node (arrêt propre).
RUN apk add --no-cache dumb-init

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production
EXPOSE 5050

# Exécution en non-root (l'utilisateur `node` existe déjà dans l'image).
USER node

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server/index.js"]
