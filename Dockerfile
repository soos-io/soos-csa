FROM node:20-slim as BASE

ARG SYFT_VERSION=v1.7.0

RUN apt-get update && apt-get install -y wget && \
    wget -qO- https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin ${SYFT_VERSION} && \
    apt-get remove -y wget && apt-get clean

COPY ./src ./src
COPY ./package.json ./package.json
COPY ./tsconfig.json ./tsconfig.json

RUN npm install
RUN npm run build

ENTRYPOINT ["node", "--no-deprecation", "dist/index.js"]