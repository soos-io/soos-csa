FROM node:24-slim AS base

# See releases on Github - https://github.com/anchore/syft/releases
ARG SYFT_VERSION=v1.37.0

RUN apt-get update && apt-get install -y wget && \
    wget -qO- https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin ${SYFT_VERSION} && \
    apt-get remove -y wget && apt-get clean

COPY ./src/ ./src/
COPY ./tsconfig.json ./
COPY ./package.json ./
COPY ./package-lock.json ./

RUN npm ci && npm run build

RUN mkdir /usr/src/app

ENTRYPOINT ["node", "--no-deprecation", "dist/index.js"]