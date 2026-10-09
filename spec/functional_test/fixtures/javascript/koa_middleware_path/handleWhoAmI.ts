import config from 'config';
import { pathToRegexp } from 'path-to-regexp';

const whoAmIPath = pathToRegexp(`${config.get<string>('basicPath')}/whoami`);
export default async function handleWhoAmI(ctx: any, next: any) {
  if (ctx.method === 'GET' && whoAmIPath.test(ctx.path)) {
    ctx.body = { ok: true };
  } else {
    await next();
  }
}
