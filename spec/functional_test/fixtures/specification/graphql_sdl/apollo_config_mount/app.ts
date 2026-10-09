import config from 'config';

const server = { applyMiddleware: (_options: unknown) => {} };
const app = {};
server.applyMiddleware({ app, path: `${config.get('basicPath')}/graphql` });
