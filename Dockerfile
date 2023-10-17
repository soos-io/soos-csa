FROM node:16-slim as BASE

RUN apt-get update && apt-get install -y wget && \
    wget -qO- https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    apt-get remove -y wget && apt-get clean

WORKDIR /usr/src/app

COPY ./src ./src
COPY ./package.json ./package.json
COPY ./tsconfig.json ./tsconfig.json

RUN npm install

RUN npm run build

ENTRYPOINT ["node", "dist/index.js"]