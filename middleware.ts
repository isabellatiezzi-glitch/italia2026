/**
 * Proteção por senha (HTTP Basic Auth) para o site inteiro.
 *
 * A senha NÃO fica no código: configure no painel do Vercel
 *   Settings → Environment Variables → SITE_PASSWORD
 * e faça um novo deploy. O usuário pedido pelo navegador pode ser qualquer um
 * (ex.: "familia") — só a senha é conferida.
 *
 * Se SITE_PASSWORD não estiver configurada, o site fica BLOQUEADO (falha fechada),
 * para nunca ir ao ar aberto por engano.
 */

/* o Vercel injeta process.env em tempo de execução; esta declaração só informa o tipo ao editor,
   já que o projeto não tem package.json nem @types/node */
declare const process: { env: Record<string, string | undefined> };

const REALM = 'Tiezzi in Toscana';

export default async function middleware(request: Request): Promise<Response | undefined> {
  const expected = process.env.SITE_PASSWORD;
  if (!expected) {
    return new Response('Site bloqueado: configure a variável SITE_PASSWORD no Vercel e faça um novo deploy.', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }

  const password = readBasicAuthPassword(request.headers.get('authorization'));
  if (password !== null && (await safeEqual(password, expected))) {
    return undefined; // senha certa: segue para o site normalmente
  }

  return new Response('Acesso restrito à família. Recarregue a página e digite a senha.', {
    status: 401,
    headers: {
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

/* "Basic base64(usuario:senha)" → senha (aceita acentos, decodificando como UTF-8) */
function readBasicAuthPassword(header: string | null): string | null {
  if (!header || !header.startsWith('Basic ')) return null;
  try {
    const bytes = Uint8Array.from(atob(header.slice(6).trim()), (c) => c.charCodeAt(0));
    const decoded = new TextDecoder().decode(bytes);
    const sep = decoded.indexOf(':');
    return sep === -1 ? null : decoded.slice(sep + 1);
  } catch {
    return null;
  }
}

/* compara pelo hash SHA-256 com tempo constante, para não vazar a senha pelo tempo de resposta */
async function safeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  const va = new Uint8Array(ha);
  const vb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < va.length; i++) diff |= va[i] ^ vb[i];
  return diff === 0;
}
