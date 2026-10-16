# Platform documents

Every version of the production platform document of the AlphaCompute confidential platform: the
file the KMS nodes, the `alpha` CLI and the signer page accept only with signatures by two of the
three release keys. Each version is here, and each of its signatures is in the public
[Rekor](https://docs.sigstore.dev/logging/overview/) transparency log, so a document the nodes are
served but nobody can see, or one signed and kept out of this repository, is noticed.

This detects; it does not prevent. The nodes do not yet refuse a document without a Rekor entry.

## Layout

- `documents/<version>.json`: the signed artifact, `{ "document": …, "signatures": [ … ] }`,
  byte for byte as published at the nodes' document URL. A file is added by a pull request with
  required review and is never changed or removed afterwards.
- `scripts/rekor.py`: logs an artifact's signatures in Rekor and runs the check below. Python 3.10+,
  standard library only.
- `.github/workflows/monitor.yml`: runs the check every hour against the URL in the repository
  variable `DOCUMENT_URL`.

## What is logged

A release signature is Ed25519 over the 32-byte digest

    D = SHA-256("alphacompute/platform/v1" || 0x00 || JCS(document))

where JCS is the RFC 8785 canonical JSON of the `document` member. Each signature is one Rekor
`rekord` entry: the artifact is `D`, the signature the raw 64 bytes, the public key the signer's
Ed25519 key in PKIX PEM. Rekor checks the signature before it accepts the entry and indexes it by
`SHA-256(D)` and by the key. Signatures and keys are public, so anyone may log them, at any time.

## Adding a version

1. Open a pull request adding `documents/<version>.json`, the artifact `alpha sign --check`
   accepts.
2. Log its signatures (anyone can; the signers usually do):

       python3 scripts/rekor.py log documents/<version>.json

   It prints each entry's UUID and log index, or `already logged`.
3. Merge once reviewed, then publish the same file at the document URL.

## Checking it yourself

    git clone <this repository> && cd platform-documents
    python3 scripts/rekor.py check <document URL>

The check fails when:

- the URL serves anything but the highest version in `documents/` (compared as JSON values);
- two files carry one version;
- a signature in any file has no Rekor entry with the same key and signature over its `D`;
- Rekor holds a signature by any key that signed a file here over a digest no file here carries:
  a document that was signed and not published.

`REKOR_URL` overrides the log (default `https://rekor.sigstore.dev`). The check trusts the log's API
answers; it does not verify inclusion proofs.
