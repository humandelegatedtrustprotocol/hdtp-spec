#!/usr/bin/env python3
"""Generate PACT 1.0 test vectors (Appendix C). Deterministic: all secrets are fixed seeds."""
import hashlib, hmac, json, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def hkdf_sha256(ikm, salt, info, L):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:L]

out = {}

# --- Fixed key material -----------------------------------------------------
seedA = bytes([0x01]) * 32          # Alina owner signing seed
seedB = bytes([0x02]) * 32          # Bharat owner signing seed
okA = Ed25519PrivateKey.from_private_bytes(seedA)
okB = Ed25519PrivateKey.from_private_bytes(seedB)
raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
pkA, pkB = raw(okA), raw(okB)
out["ownerA"] = {"seed": seedA.hex(), "pub": b64u(pkA)}
out["ownerB"] = {"seed": seedB.hex(), "pub": b64u(pkB)}

# --- C.2 SAS derivation ------------------------------------------------------
pact_id = bytes.fromhex("00112233445566778899aabbccddeeff")
nA = bytes.fromhex("a0" * 16)
nB = bytes.fromhex("b0" * 16)
lo, hi = sorted([pkA, pkB])
ikm = lo + hi
info = b"PACT-1.0 sas" + nA + nB
okm = hkdf_sha256(ikm, pact_id, info, 9)          # 72 bits
bits = int.from_bytes(okm, "big")
idxs = [(bits >> (72 - 11 * (i + 1))) & 0x7FF for i in range(6)]
num = int.from_bytes(okm[:6], "big") % (10 ** 12)
out["sas"] = {"pactId": pact_id.hex(), "nA": nA.hex(), "nB": nB.hex(),
              "sortedIkm": ikm.hex(), "okm": okm.hex(),
              "wordIndexes": idxs, "numeric": f"{num:012d}"}

# --- C.3 reqHash over exact JWS bytes ---------------------------------------
def jws_eddsa(payload_obj, key):
    ph = b64u(json.dumps({"alg": "EdDSA", "typ": "pact-pair+jws"},
                          separators=(",", ":")).encode())
    pl = b64u(json.dumps(payload_obj, separators=(",", ":"), sort_keys=False).encode())
    si = f"{ph}.{pl}".encode()
    return f"{ph}.{pl}.{b64u(key.sign(si))}"

req = {"type": "pact.pair.request", "pactId": b64u(pact_id), "sasCommit": b64u(hashlib.sha256(nB).digest())}
jws = jws_eddsa(req, okB)
out["reqHash"] = {"jws": jws, "sha256": hashlib.sha256(jws.encode()).hexdigest()}

# --- C.4 HPKE Auth-mode envelope seal ---------------------------------------
suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)
skS = X25519PrivateKey.from_private_bytes(bytes([0x03]) * 32)   # sender agent KEM key
skR = X25519PrivateKey.from_private_bytes(bytes([0x04]) * 32)   # recipient agent KEM key
rawx = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
pkSb, pkRb = rawx(skS), rawx(skR)
kemS = KEMKey.from_pyca_cryptography_key(skS)
kemRpub = KEMKey.from_pyca_cryptography_key(skR.public_key())
kemRpriv = KEMKey.from_pyca_cryptography_key(skR)

protected = {"v": 1, "suite": "PACT-HPKE-1", "pactId": b64u(pact_id), "from": "did:key:zA", "to": "did:key:zB",
             "dir": "r2i", "seq": 7, "msgId": b64u(bytes(range(16))), "ts": 1756000000, "exp": 1756003600,
             "cty": "application/pact-msg+json", "kid": "ek-r-1", "skid": "ek-s-1"}
prot_b = json.dumps(protected, separators=(",", ":"), sort_keys=False).encode()
info = b"PACT-1.0 env" + b64u(pact_id).encode()
plaintext = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "message/send",
                        "params": {"message": {"role": "user", "parts": [{"kind": "text", "text": "hello"}]}}},
                       separators=(",", ":")).encode()
# deterministic encap is impossible (ephemeral); so we seal once and record enc+ct for a *decryption* vector
enc, sender_ctx = suite.create_sender_context(kemRpub, info=info, sks=kemS)
ct = sender_ctx.seal(plaintext, aad=prot_b)
# verify decryption
rctx = suite.create_recipient_context(enc, kemRpriv, info=info, pks=KEMKey.from_pyca_cryptography_key(skS.public_key()))
assert rctx.open(ct, aad=prot_b) == plaintext
out["envelope"] = {"skS_seed": "03"*32, "skR_seed": "04"*32, "pkS": b64u(pkSb), "pkR": b64u(pkRb),
                   "info": info.hex(), "protected": protected, "protected_bytes_b64u": b64u(prot_b),
                   "enc": b64u(enc), "ct": b64u(ct), "pt": plaintext.decode()}

# --- C.5 route id / 9421 content digest -------------------------------------
env_json = json.dumps({"protected": b64u(prot_b), "enc": b64u(enc), "ct": b64u(ct)}, separators=(",", ":")).encode()
out["contentDigest"] = {"envelope_bytes_sha256_b64": base64.b64encode(hashlib.sha256(env_json).digest()).decode(),
                        "envelope": env_json.decode()[:120] + "..."}

print(json.dumps(out, indent=2))
