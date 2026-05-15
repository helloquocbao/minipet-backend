# Use a modern Node.js runtime
FROM node:22-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose the port the app runs on
EXPOSE 3001

# Start the server
CMD ["npm", "start"]
