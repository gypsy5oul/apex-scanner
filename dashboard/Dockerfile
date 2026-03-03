# ============================================================
# Stage 1: Build — compile React app with Node.js
# ============================================================
FROM registry.access.redhat.com/ubi9/nodejs-20 AS build

# UBI Node.js image uses /opt/app-root/src as WORKDIR and runs as user 1001
WORKDIR /opt/app-root/src

# Copy package files first for layer caching (with correct ownership)
COPY --chown=1001:0 package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY --chown=1001:0 . .

# Build the app
RUN npm run build

# ============================================================
# Stage 2: Runtime — serve with UBI nginx
# ============================================================
FROM registry.access.redhat.com/ubi9/nginx-124 AS runtime

# Copy build output to UBI nginx default web root
COPY --from=build /opt/app-root/src/build /opt/app-root/src

# Copy custom nginx config into the default server block includes
COPY --chmod=644 nginx.conf /opt/app-root/etc/nginx.default.d/custom.conf

# UBI nginx runs as non-root on port 8080
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
