#!/usr/bin/env python3
"""Log a platform document's release signatures in Rekor, and check that the document the nodes
are served, the documents in this repository and Rekor agree.

  rekor.py log documents/<version>.json
  rekor.py check <document URL>

Every release signature is Ed25519 over D = SHA-256("alphacompute/platform/v1" || 0x00 ||
JCS(document)). Rekor's `rekord` entry verifies pure Ed25519 over a whole artifact, so each
signature is logged as one `rekord` entry whose artifact is the 32 bytes of D.
"""

import base64
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

REKOR = os.environ.get("REKOR_URL", "https://rekor.sigstore.dev")
CONTEXT = b"alphacompute/platform/v1"
DOCUMENTS = pathlib.Path(__file__).resolve().parent.parent / "documents"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def no_floats(s):
    raise ValueError(f"a float ({s}) in a platform document")


def load(raw):
    return json.loads(raw, parse_float=no_floats)


def digest(document):
    # Serialization equals RFC 8785 for documents without floats and with BMP keys; any
    # difference changes D, which fails the check rather than passing it.
    jcs = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(CONTEXT + b"\x00" + jcs.encode()).digest()


def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64(b):
    return base64.b64encode(b).decode()


def pem(raw_key):
    der = base64.encodebytes(ED25519_SPKI_PREFIX + raw_key).decode()
    return f"-----BEGIN PUBLIC KEY-----\n{der}-----END PUBLIC KEY-----\n".encode()


def signatures(artifact):
    """(D, [(PEM public key, raw signature)]) of an artifact."""
    pairs = []
    for s in artifact["signatures"]:
        if s["algorithm"] != "ed25519":
            raise ValueError(f"signature algorithm {s['algorithm']}")
        pairs.append((pem(b64url(s["key"])), b64url(s["signature"])))
    return digest(artifact["document"]), pairs


def call(method, path, body=None):
    request = urllib.request.Request(
        REKOR + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def log(path):
    d, pairs = signatures(load(pathlib.Path(path).read_bytes()))
    for key, sig in pairs:
        entry = {
            "kind": "rekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {"format": "x509", "content": b64(sig), "publicKey": {"content": b64(key)}},
                "data": {"content": b64(d)},
            },
        }
        try:
            for uuid, e in call("POST", "/api/v1/log/entries", entry).items():
                print(f"logged {uuid} at index {e['logIndex']}")
        except urllib.error.HTTPError as e:
            if e.code != 409:
                raise SystemExit(f"Rekor refused the entry: {e.code} {e.read().decode()}")
            print(f"already logged: {e.headers.get('Location', '')}")


def search(query):
    """The `rekord` entries an index query finds, as (hash hex, PEM key, raw signature)."""
    found = []
    for uuid in call("POST", "/api/v1/index/retrieve", query):
        for e in call("GET", f"/api/v1/log/entries/{uuid}").values():
            body = json.loads(base64.b64decode(e["body"]))
            if body.get("kind") != "rekord":
                continue
            spec = body["spec"]
            found.append((
                spec["data"]["hash"]["value"],
                base64.b64decode(spec["signature"]["publicKey"]["content"]),
                base64.b64decode(spec["signature"]["content"]),
            ))
    return found


def check(url):
    failures = []
    artifacts = {}
    for path in sorted(DOCUMENTS.glob("*.json")):
        artifact = load(path.read_bytes())
        version = artifact["document"]["version"]
        if version in artifacts:
            failures.append(f"{path.name}: version {version} is in two files")
        artifacts[version] = artifact
    if not artifacts:
        raise SystemExit("no documents in git")

    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        served = load(response.read())
    latest = max(artifacts)
    if served != artifacts[latest]:
        failures.append(
            f"{url} serves version {served.get('document', {}).get('version')}, "
            f"not the latest file in git (version {latest}) as committed"
        )

    hashes, keys = set(), set()
    for version, artifact in sorted(artifacts.items()):
        d, pairs = signatures(artifact)
        h = hashlib.sha256(d).hexdigest()
        hashes.add(h)
        logged = {(k, s) for hh, k, s in search({"hash": f"sha256:{h}"}) if hh == h}
        for key, sig in pairs:
            keys.add(key)
            if (key, sig) not in logged:
                failures.append(f"version {version}: a signature is not in Rekor")

    # A release key's signature over a digest no document in git has: a document signed and not
    # published here.
    for key in sorted(keys):
        for h, _, _ in search({"publicKey": {"format": "x509", "content": b64(key)}}):
            if h not in hashes:
                failures.append(f"Rekor has a signature over {h} that no document in git carries")

    for f in failures:
        print(f"FAIL {f}")
    if failures:
        raise SystemExit(1)
    print(f"ok: {url} serves version {latest}; {len(artifacts)} documents and their signatures are in Rekor")


if __name__ == "__main__":
    match sys.argv[1:]:
        case ["log", path]:
            log(path)
        case ["check", url]:
            check(url)
        case _:
            raise SystemExit(__doc__)
