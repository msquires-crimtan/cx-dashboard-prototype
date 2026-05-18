# syntax=docker/dockerfile:1
FROM node:20-alpine AS base
WORKDIR /app

# Install git
RUN apk add --no-cache git

# Configure git identity for commits
RUN git config --global user.email "editor@crimtan.com" && \
    git config --global user.name "TravelID Editor"

# Install dependencies
COPY package.json ./
RUN npm install --omit=dev

# Copy source
COPY server.js ./
COPY public/ ./public/

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "server.js"]
