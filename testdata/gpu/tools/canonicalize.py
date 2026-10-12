#!/usr/bin/env python3
"""Turns one NVIDIA RIM (TCG/SWID XML with an enveloped XML-DSig signature) into the entry the
local GPU verifier reads, so that the KMS never canonicalises XML itself.

    canonicalize.py <rim.xml | rim-service.json> [<id>]  >  entry.json

The entry holds the two byte strings XML-DSig's processing produces, the signature, and the
signing certificate chain:

    {"id": ..., "signed_info": b64, "document": b64, "signature": b64, "certificates": [b64 DER]}

- signed_info: Canonical XML of ds:SignedInfo in its document context (the bytes the signature
  covers);
- document:    Canonical XML of the document after the enveloped-signature transform (the bytes
  ds:DigestValue is over).

NVIDIA signs with Canonical XML 1.1. lxml implements Canonical XML 1.0; the two produce the same
bytes unless an ancestor of a canonicalised subtree carries xml:id or xml:base, which this script
refuses. Nothing here is trusted by the verifier: it checks the signature over signed_info, that
SHA-384(document) is the signed DigestValue, and the certificate chain, so a wrong
canonicalisation can only make the entry fail. The script checks the same before writing, so a
refresh fails here rather than in the KMS.

Requires lxml and cryptography. Input is parsed with entity resolution and network access off.
"""

import base64
import hashlib
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from lxml import etree

DS = "http://www.w3.org/2000/09/xmldsig#"
XML_NS = "http://www.w3.org/XML/1998/namespace"


def parse(raw):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False,
                             huge_tree=False, remove_blank_text=False)
    return etree.fromstring(raw, parser)


def main():
    path = sys.argv[1]
    raw = open(path, "rb").read()
    rim_id = sys.argv[2] if len(sys.argv) > 2 else None
    if raw.lstrip().startswith(b"{"):
        reply = json.loads(raw)  # NVIDIA RIM service: {"id", "rim": base64, ...}
        rim_id = rim_id or reply["id"]
        raw = base64.b64decode(reply["rim"])
    root = parse(raw)
    signatures = root.findall(f".//{{{DS}}}Signature")
    if len(signatures) != 1 or signatures[0].getparent() is not root:
        sys.exit("expected exactly one enveloped ds:Signature under the root")
    signature = signatures[0]
    for element in [root, signature]:
        for attr in ("id", "base"):
            if element.get(f"{{{XML_NS}}}{attr}") is not None:
                sys.exit(f"xml:{attr} on an ancestor: Canonical XML 1.0 and 1.1 differ here")
    signed_info = etree.tostring(signature.find(f"{{{DS}}}SignedInfo"), method="c14n",
                                 exclusive=False, with_comments=False)
    value = base64.b64decode("".join(signature.findtext(f"{{{DS}}}SignatureValue").split()))
    certificates = [base64.b64decode("".join(e.text.split()))
                    for e in signature.iter(f"{{{DS}}}X509Certificate")]

    # The enveloped-signature transform: the document without the Signature element (its tail
    # text stays where it was).
    document_root = parse(raw)
    enveloped = document_root.find(f"{{{DS}}}Signature")
    tail = enveloped.tail or ""
    previous = enveloped.getprevious()
    if previous is not None:
        previous.tail = (previous.tail or "") + tail
    else:
        document_root.text = (document_root.text or "") + tail
    document_root.remove(enveloped)
    document = etree.tostring(document_root, method="c14n", exclusive=False, with_comments=False)

    digest = base64.b64decode(parse(signed_info).findtext(f".//{{{DS}}}DigestValue"))
    if hashlib.sha384(document).digest() != digest:
        sys.exit("canonical document does not match the signed DigestValue")
    signer = x509.load_der_x509_certificate(certificates[0])
    half = len(value) // 2
    der_signature = encode_dss_signature(int.from_bytes(value[:half], "big"),
                                         int.from_bytes(value[half:], "big"))
    signer.public_key().verify(der_signature, signed_info, ec.ECDSA(hashes.SHA384()))

    b64 = lambda b: base64.b64encode(b).decode()
    json.dump({
        "id": rim_id,
        "signed_info": b64(signed_info),
        "document": b64(document),
        "signature": b64(value),
        "certificates": [b64(c) for c in certificates],
    }, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
