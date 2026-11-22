"""Svetainės turinio iššifravimas / užšifravimas (AES-GCM, PBKDF2-SHA256).
  python3 tools/site.py decrypt <slaptažodis> <aplankas>   – app.enc + data/*.enc → <aplankas>/index.html, data/*
  python3 tools/site.py encrypt <slaptažodis> <aplankas>   – <aplankas> → app.enc + data/*.enc (nauja druska, index.html atnaujinamas)
Turinys repozitorijoje laikomas tik užšifruotas."""
import os, re, sys, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mode, pw, d = sys.argv[1], sys.argv[2].encode(), os.path.abspath(sys.argv[3])
idx = os.path.join(ROOT, "index.html"); h = open(idx).read()
ITER = int(re.search(r"ITER = (\d+)", h).group(1))
def key(salt): return AESGCM(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw))
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
print(mode, "ok")
