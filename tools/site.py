"""Svetainės turinio iššifravimas / užšifravimas (AES-GCM, PBKDF2-SHA256).
  python3 tools/site.py decrypt <slaptažodis> <aplankas>   – app.enc + data/*.enc → <aplankas>/index.html, data/*
  python3 tools/site.py encrypt <slaptažodis> <aplankas>   – <aplankas> → app.enc + data/*.enc (nauja druska, index.html atnaujinamas)
Turinys repozitorijoje laikomas tik užšifruotas."""
import os, re, sys, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mode, pw, d = sys.argv[1], sys.argv[2].encode(), os.path.abspath(sys.argv[3])
idx = os.path.join(ROOT, "index.html"); h = open(idx).read()
ITER = int(re.search(r"ITER = (\d+)", h).group(1))
def key(salt): return AESGCM(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw))
def write_sw():
    files = ["./", "index.html", "app.enc", "manifest.webmanifest", "icons/icon-192.png", "icons/icon-180.png"] + ["data/" + f for f in sorted(os.listdir(ROOT + "/data")) if not f.startswith("rez.pdf")]
    ver = base64.b16encode(os.urandom(4)).decode().lower()
    open(ROOT + "/sw.js", "w").write("""const V = "smk-%s", PRE = %s;
self.addEventListener("install", e => { e.waitUntil(caches.open(V).then(c => c.addAll(PRE)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url); if (e.request.method !== "GET" || u.origin !== location.origin) return;
  e.respondWith(caches.open(V).then(async c => { const hit = await c.match(e.request, { ignoreSearch: true }); if (hit) return hit;
    try { const r = await fetch(e.request); if (r.ok) c.put(e.request, r.clone()); return r; } catch (x) { return (await c.match("index.html")) || Response.error(); } }));
});
""" % (ver, json.dumps(files)))
if mode == "decrypt":
    a = key(base64.b64decode(re.search(r'SALT = "([^"]+)"', h).group(1)))
    dec = lambda p: (lambda b: a.decrypt(b[:12], b[12:], None))(open(p, "rb").read())
    os.makedirs(d + "/data", exist_ok=True)
    open(d + "/index.html", "wb").write(dec(ROOT + "/app.enc"))
    for f in os.listdir(ROOT + "/data"):
        open(d + "/data/" + f[:-4], "wb").write(dec(ROOT + "/data/" + f))
elif mode == "encrypt":
    salt = os.urandom(16); a = key(salt)
    enc = lambda b: (lambda iv: iv + a.encrypt(iv, b, None))(os.urandom(12))
    open(ROOT + "/app.enc", "wb").write(enc(open(d + "/index.html", "rb").read()))
    for f in os.listdir(ROOT + "/data"): os.remove(ROOT + "/data/" + f)
    for f in os.listdir(d + "/data"):
        open(ROOT + "/data/" + f + ".enc", "wb").write(enc(open(d + "/data/" + f, "rb").read()))
    open(idx, "w").write(re.sub(r'SALT = "[^"]+"', 'SALT = "' + base64.b64encode(salt).decode() + '"', h))
    write_sw()
if mode == "sw": write_sw()
print(mode, "ok")
