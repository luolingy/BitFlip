#!/usr/bin/env node
/**
 * BitFlip —— crates.io 本地稀疏索引代理（开发工具，非运行时组件）。
 *
 * 为什么需要它：
 *   本机 cargo 通过 libcurl + Windows Schannel 出网时拿不到凭证
 *   （`curl: (35) schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS`），
 *   表现为 `cargo fetch` → `download of config.json failed / curl failed`。
 *   而 Node（OpenSSL）出网正常。于是让 cargo 只跟 127.0.0.1 说**明文 HTTP**，
 *   由本进程用 Node 的 fetch 去访问上游索引与 .crate 包。
 *
 * 用法：
 *   node scripts/crates-proxy.mjs                  # 监听 127.0.0.1:8765，前台运行
 *   node scripts/crates-proxy.mjs --port 8799      # 换端口
 *   然后（另开一个终端）：
 *   cargo fetch --config scripts/crates-proxy.toml
 *   cargo add <crate> --config scripts/crates-proxy.toml
 *
 * 注意：
 *   - 只在**需要拉新依赖**时启动；依赖已在本地缓存后，普通 `cargo build/test`
 *     不需要它（Cargo.lock 已入库，可离线复现）。
 *   - 磁盘缓存放在 .crates-proxy-cache/（已 gitignore），避免重复下载。
 *   - 只读代理：不接收上传，不写仓库，不需要鉴权；仅绑定回环地址。
 */
import { createServer } from 'node:http';
import { createReadStream, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');

// ── 参数 ────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = {
    port: 8765,
    host: '127.0.0.1',
    indexUpstream: 'https://index.crates.io',
    dlUpstream: 'https://static.crates.io/crates',
    cacheDir: join(REPO_ROOT, '.crates-proxy-cache'),
    quiet: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--port') out.port = Number(next());
    else if (a === '--host') out.host = next();
    else if (a === '--index-upstream') out.indexUpstream = next().replace(/\/$/, '');
    else if (a === '--dl-upstream') out.dlUpstream = next().replace(/\/$/, '');
    else if (a === '--cache-dir') out.cacheDir = resolve(next());
    else if (a === '--quiet') out.quiet = true;
    else if (a === '--help' || a === '-h') {
      console.log(readFileSync(fileURLToPath(import.meta.url), 'utf-8').split('*/')[0]);
      process.exit(0);
    }
  }
  return out;
}

const opts = parseArgs(process.argv.slice(2));
const INDEX_CACHE = join(opts.cacheDir, 'index');
const DL_CACHE = join(opts.cacheDir, 'dl');

mkdirSync(INDEX_CACHE, { recursive: true });
mkdirSync(DL_CACHE, { recursive: true });

function log(...parts) {
  if (!opts.quiet) console.error('[crates-proxy]', ...parts);
}

/** 把 URL 路径段映射到磁盘缓存路径，并确保不逃出缓存根目录。 */
function cachePathFor(root, relPath) {
  const safe = relPath
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .join('/');
  if (!safe) return null;
  return join(root, safe);
}

/** 上游 GET；非 2xx 抛错，交由调用方转成 502/404。 */
async function upstream(url) {
  const res = await fetch(url, { redirect: 'follow' });
  return res;
}

async function sendBuffered(res, status, contentType, body) {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function sendFileOrBody(res, status, contentType, body, cachePath) {
  if (cachePath) {
    mkdirSync(dirname(cachePath), { recursive: true });
    writeFileSync(cachePath, body);
  }
  await sendBuffered(res, status, contentType, body);
}

// ── 路由 ────────────────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${opts.host}:${opts.port}`);
  const path = decodeURIComponent(url.pathname);

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return void sendBuffered(res, 405, 'text/plain; charset=utf-8', 'method not allowed\n');
  }

  try {
    // 1) 稀疏索引的 config.json —— 把 dl 指向本代理。
    if (path === '/index/config.json') {
      const up = await upstream(`${opts.indexUpstream}/config.json`);
      if (!up.ok) return void sendBuffered(res, 502, 'text/plain; charset=utf-8', 'upstream error\n');
      const raw = JSON.parse(await up.text());
      raw.dl = `http://${opts.host}:${opts.port}/dl/{crate}/{crate}-{version}.crate`;
      // api 字段对只读代理无意义，保留上游值以免 cargo 误判。
      return void sendBuffered(res, 200, 'application/json', JSON.stringify(raw));
    }

    // 2) 稀疏索引条目：/index/{prefix...}/{crate}
    if (path.startsWith('/index/')) {
      const rel = path.slice('/index/'.length);
      const cachePath = cachePathFor(INDEX_CACHE, rel);
      if (cachePath && existsSync(cachePath)) {
        const body = readFileSync(cachePath);
        log('index HIT', rel);
        return void sendBuffered(res, 200, 'text/plain; charset=utf-8', body);
      }
      const up = await upstream(`${opts.indexUpstream}/${rel}`);
      if (up.status === 404) {
        return void sendBuffered(res, 404, 'text/plain; charset=utf-8', 'not found\n');
      }
      if (!up.ok) {
        log('index UPSTREAM-ERR', up.status, rel);
        return void sendBuffered(res, 502, 'text/plain; charset=utf-8', 'upstream error\n');
      }
      const body = Buffer.from(await up.arrayBuffer());
      log('index FETCH', rel, `${body.length}B`);
      return void sendFileOrBody(res, 200, 'text/plain; charset=utf-8', body, cachePath);
    }

    // 3) 包下载：/dl/{crate}/{crate}-{version}.crate
    if (path.startsWith('/dl/')) {
      const rel = path.slice('/dl/'.length);
      const cachePath = cachePathFor(DL_CACHE, rel);

      res.setHeader('content-type', 'application/octet-stream');
      if (cachePath && existsSync(cachePath)) {
        const { size } = await import('node:fs').then((m) => m.promises.stat(cachePath));
        res.writeHead(200, { 'content-length': size });
        if (req.method === 'HEAD') return void res.end();
        log('crate HIT', rel, `${size}B`);
        return void createReadStream(cachePath).pipe(res);
      }

      const up = await upstream(`${opts.dlUpstream}/${rel}`);
      if (!up.ok || !up.body) {
        log('crate UPSTREAM-ERR', up.status, rel);
        return void sendBuffered(res, 502, 'text/plain; charset=utf-8', 'upstream error\n');
      }
      const len = up.headers.get('content-length');
      const headers = {};
      if (len) headers['content-length'] = len;
      res.writeHead(200, headers);
      if (req.method === 'HEAD') return void res.end();

      const chunks = [];
      for await (const chunk of Readable.fromWeb(up.body)) chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (cachePath) {
        mkdirSync(dirname(cachePath), { recursive: true });
        writeFileSync(cachePath, buf);
      }
      log('crate FETCH', rel, `${buf.length}B`);
      return void res.end(buf);
    }

    // 4) 健康检查，便于脚本确认代理已就绪。
    if (path === '/healthz') {
      const cfg = `sparse+http://${opts.host}:${opts.port}/index/`;
      return void sendBuffered(
        res,
        200,
        'application/json',
        JSON.stringify({ ok: true, source: cfg, cacheDir: opts.cacheDir }),
      );
    }

    return void sendBuffered(res, 404, 'text/plain; charset=utf-8', 'not found\n');
  } catch (err) {
    log('ERROR', path, err instanceof Error ? err.message : String(err));
    return void sendBuffered(res, 502, 'text/plain; charset=utf-8', 'proxy error\n');
  }
});

server.listen(opts.port, opts.host, () => {
  log(`listening on http://${opts.host}:${opts.port}`);
  log(`cargo 源替换: sparse+http://${opts.host}:${opts.port}/index/`);
  log(`索引上游: ${opts.indexUpstream}   包上游: ${opts.dlUpstream}`);
  log(`磁盘缓存: ${opts.cacheDir}`);
  log('使用: cargo fetch --config scripts/crates-proxy.toml');
});
