FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
# ClamAV is used for the production upload gate. Keep its database in the
# image/runtime volume and refresh it as part of the image release process.
RUN apk add --no-cache clamav clamav-daemon && freshclam || true
COPY . .
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["node","backend/server.js"]
