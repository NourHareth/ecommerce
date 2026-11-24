# Build from this directory: docker build -t amcart-ui:latest .

# ---- build stage: compiles the SPA; nothing from here except /app/dist reaches the final image
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ENV VITE_USER_SERVICE_URL=
# Same-origin /api: nginx routes /api/v1/* to the right backend service.
ENV VITE_PRODUCT_SERVICE_URL=/api
RUN npm run build

# ---- runtime stage: unprivileged nginx (UID 101), listens on 8080
# Files are copied as root:root, read-only for nginx: a compromised worker cannot
# rewrite the site or its own configuration. Runtime writes go to /tmp only.
FROM nginxinc/nginx-unprivileged:1.31-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx/nginx-main.conf /etc/nginx/nginx.conf
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY nginx/snippets /etc/nginx/snippets
USER 101
EXPOSE 8080
