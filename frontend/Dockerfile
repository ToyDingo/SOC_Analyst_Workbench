FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY . .

EXPOSE 3000

#CMD ["npm", "run", "dev", "--", "--hostname", "0.0.0.0", "--port", "3000"] # For localhost development
CMD ["sh", "-c", "npm run dev -- --hostname 0.0.0.0 --port ${PORT:-8080}"] # For Google Cloud Run, use the PORT environment variable

