import Koa from 'koa';
import handleWhoAmI from './handleWhoAmI';

const app = new Koa();
app.use(handleWhoAmI);
