// Service worker do cofre (spec 12.2). Guarda os ficheiros cifrados; com a chave, decifra-os ao servir.
// A chave entra pela porta (postMessage) e importa-se como CryptoKey NÃO-extraível e fica sempre no IndexedDB deste
// service worker (o navegador para-o ao fim de ≈ 30 s parado e a memória perde-se). Com «lembrar» não expira; sem
// «lembrar», expira ao fim de 30 min sem uso. Sem chave: as navegações recebem a porta e o cofre dá 403.
const VERSAO = '851fd2620803';
const CACHE = 'tanda-poc-' + VERSAO;
const ESCOPO = new URL(self.registration.scope).pathname;           // ex.: /tanda-poc/
const SESSAO_MS = 30 * 60 * 1000;
let chave = null;
let cofre = null;

function abrirBase() {
  return new Promise((ok, falha) => {
    const r = indexedDB.open('tanda-poc-sw', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('chave');
    r.onsuccess = () => ok(r.result);
    r.onerror = () => falha(r.error);
  });
}
async function lerChaveGuardada() {
  const d = await abrirBase();
  return new Promise(ok => { const q = d.transaction('chave').objectStore('chave').get('k'); q.onsuccess = () => ok(q.result || null); q.onerror = () => ok(null); });
}
async function guardarChave(registo) {
  const d = await abrirBase();
  return new Promise(ok => { const t = d.transaction('chave', 'readwrite'); t.objectStore('chave').put(registo, 'k'); t.oncomplete = () => ok(); t.onerror = () => ok(); });
}
// registo = { k: CryptoKey, expira: ms | null }; null = «lembrar» (não expira)
async function obterChave() {
  if (!chave) chave = await lerChaveGuardada();
  if (!chave) return null;
  if (!('k' in chave)) chave = { k: chave, expira: null };   // versão anterior: guardava só a CryptoKey («lembrar»)
  if (chave.expira !== null && Date.now() > chave.expira) { chave = null; await guardarChave(null); return null; }
  if (chave.expira !== null) { chave.expira = Date.now() + SESSAO_MS; void guardarChave(chave); }
  return chave.k;
}
async function obterCofre() {
  if (cofre) return cofre;
  const c = await caches.open(CACHE);
  const r = (await c.match(ESCOPO + 'cofre.json')) || (await fetch(ESCOPO + 'cofre.json'));
  cofre = await r.clone().json();
  return cofre;
}

self.addEventListener('install', ev => {
  ev.waitUntil((async () => {
    const r = await fetch(ESCOPO + 'cofre.json', { cache: 'no-cache' });
    const C = await r.clone().json();
    const c = await caches.open(CACHE);
    await c.put(ESCOPO + 'cofre.json', r);
    const claros = ['', 'index.html', 'manifest.webmanifest', 'icones/icon-192.png', 'icones/apple-touch-icon.png', 'icones/favicon-32.png'];
    // cache: 'reload' — nunca a cache HTTP do navegador (o Pages manda max-age=600: uma publicação recente
    // misturaria um app.html antigo com bundles novos)
    await c.addAll(claros.map(p => new Request(ESCOPO + p, { cache: 'reload' })));
    await c.addAll(Object.keys(C.ficheiros).map(p => new Request(ESCOPO + p, { cache: 'reload' })));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', ev => {
  ev.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith('tanda-poc-') && k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('message', ev => {
  const porta = ev.ports[0];
  const d = ev.data || {};
  (async () => {
    if (d.tipo === 'tem-chave') return porta.postMessage({ tem: !!(await obterChave()) });
    if (d.tipo === 'chave') {
      const k = await crypto.subtle.importKey('raw', d.bytes, { name: 'AES-GCM' }, false, ['decrypt']);
      chave = { k, expira: d.lembrar ? null : Date.now() + SESSAO_MS };
      await guardarChave(chave);
      return porta.postMessage({ ok: true });
    }
  })().catch(() => porta && porta.postMessage({ ok: false }));
});

async function decifrado(caminho, tipo) {
  const k = await obterChave();
  if (!k) return null;
  const c = await caches.open(CACHE);
  let r = await c.match(ESCOPO + caminho);
  if (!r) { r = await fetch(ESCOPO + caminho); if (r.ok) await c.put(ESCOPO + caminho, r.clone()); }
  const b = new Uint8Array(await r.arrayBuffer());
  const claro = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, k, b.slice(12));
  return new Response(claro, { headers: { 'content-type': tipo } });
}

async function daCache(pedido) {
  const c = await caches.open(CACHE);
  return (await c.match(pedido, { ignoreSearch: true })) || fetch(pedido);
}

self.addEventListener('fetch', ev => {
  const url = new URL(ev.request.url);
  if (url.origin !== location.origin || !url.pathname.startsWith(ESCOPO) || ev.request.method !== 'GET') return;
  const caminho = url.pathname.slice(ESCOPO.length);
  ev.respondWith((async () => {
    if (ev.request.mode === 'navigate') {
      const app = await decifrado('app.html', 'text/html; charset=utf-8').catch(() => null);
      return app || (await caches.open(CACHE).then(c => c.match(ESCOPO + 'index.html'))) || fetch(ev.request);
    }
    const C = await obterCofre().catch(() => null);
    const tipo = C && C.ficheiros[caminho];
    if (tipo) return (await decifrado(caminho, tipo).catch(() => null)) || new Response('', { status: 403 });
    return daCache(ev.request);
  })());
});
