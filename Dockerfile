FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install --omit=dev

# Copy source
COPY . .

EXPOSE 3020

CMD ["node", "server.js"]
