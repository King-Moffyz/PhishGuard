FROM node:18-alpine AS build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend .

# Vite inlines VITE_* vars into the static bundle at build time (import.meta.env), not at
# container runtime — a docker-compose `environment:` block on the final "serve" stage would
# be silently ineffective. These build args are the only way to make them configurable.
ARG VITE_API_BASE_URL=http://localhost:8000
ARG VITE_DEFAULT_ORG_ID
ARG VITE_DEFAULT_ACCOUNT_ID
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_DEFAULT_ORG_ID=$VITE_DEFAULT_ORG_ID
ENV VITE_DEFAULT_ACCOUNT_ID=$VITE_DEFAULT_ACCOUNT_ID

RUN npm run build

FROM node:18-alpine
WORKDIR /app
RUN npm install -g serve
COPY --from=build /app/dist ./dist
EXPOSE 3000
CMD ["serve", "-s", "dist", "-l", "3000"]
