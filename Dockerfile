FROM node:22-alpine
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 DATA_DIR=/data UPLOAD_DIR=/data/files
WORKDIR /app
COPY backend/package.json backend/
COPY backend/src backend/src
COPY frontend frontend
RUN addgroup -S tv && adduser -S tv -G tv && mkdir -p /data && chown -R tv:tv /data
USER tv
VOLUME /data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- "http://127.0.0.1:${PORT:-3000}/healthz" || exit 1
WORKDIR /app/backend
# FILE_ENC_KEY and AUDIT_HMAC_KEY (64 hex each) must be supplied as environment variables; startup fails without them.
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.js"]
