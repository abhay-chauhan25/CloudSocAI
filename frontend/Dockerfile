# CloudSOC dashboard: built with Node, served by nginx.
#
#   docker build -t cloudsoc-frontend frontend/
#
# Two stages: the first has Node, npm, and every dev dependency; the final
# image has only nginx and the built static files (no Node, no source).

FROM node:22.23.3-alpine3.24 AS build
WORKDIR /src
# Dependencies first, so code changes reuse the cached install layer.
# `npm ci` installs exactly what package-lock.json records.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# nginx-unprivileged listens on 8080 and runs as a non-root user.
FROM nginxinc/nginx-unprivileged:1.31.7-alpine3.24
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
