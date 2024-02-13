FROM node:18-alpine

LABEL maintainer="Michael Coleman Michael@f5.com"

RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app

WORKDIR /home/node/app

COPY package*.json ./

RUN npm install

COPY --chown=node:node . .

USER node

EXPOSE 3000

CMD [ "node", "server.js" ]