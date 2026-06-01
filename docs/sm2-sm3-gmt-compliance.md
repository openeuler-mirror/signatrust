# SM2/SM3 GM/T Cryptographic Algorithm Support in Signatrust

## Introduction

Signatrust supports SM2 (elliptic curve public key) and SM3 (cryptographic hash) algorithms
for CMS signing, X.509 certificate issuance, and CRL (Certificate Revocation List) signing
in compliance with the Chinese national cryptographic standards **GM/T 0003-2012**.

The SM2/SM3 algorithm suite is widely required in industries such as finance, government,
and critical infrastructure within China, where national cryptographic algorithms are mandated
for data integrity, authentication, and non-repudiation.

Support for SM2/SM3 enables Signatrust to serve as a unified signing platform for environments
that require GM/T-compliant signatures, side-by-side with international algorithms (RSA, ECDSA).

---

## Key Concepts

### SM2 User ID and the Z Value

A distinguishing feature of the SM2 signature scheme defined in **GM/T 0003.2-2012** is the
requirement to incorporate a **user identifier** (distinguishing identifier) when computing
the Z value (the hash of the signer's distinguishable identifier, elliptic curve parameters,
and public key). The Z value is then prefixed to the message before computing the final hash
used in the signature.

The default SM2 user ID is defined as the 16-byte ASCII string:

```
SM2_DEFAULT_ID = "1234567812345678"
```

If the SM2 user ID is **not set** during signing or verification, the Z value computation
will differ, producing signatures that fail verification under GM/T-compliant tools.

---

## Differences from Standard CMS (PKCS#7)

Signatrust's SM2 CMS signing differs from standard OpenSSL/RSA-based CMS signing in several
ways, as mandated by **GM/T 0010** (the Chinese national standard for CMS with SM2/SM3).

### Comparison Table

| Aspect | Standard CMS (RSA) | SM2 CMS (GM/T 0010) |
|--------|-------------------|---------------------|
| **Key type** | RSA, integer factorization | SM2, elliptic curve (OID 1.2.156.10197.1.301) |
| **Digest algorithm** | SHA-256/SHA-512 | SM3 (256-bit) |
| **Signing API** | `CMS_sign()` — OpenSSL handles everything internally | `EVP_DigestSignInit` + `EVP_PKEY_CTX_set1_id` + manual CMS operations — `CMS_sign()` cannot set SM2 ID |
| **Padding** | PSS (`RSA_PKCS1_PSS_PADDING`) | None (ECC-based, no padding) |
| **Signer ID** | Not required | `EVP_PKEY_CTX_set1_id(ctx, "1234567812345678")` — must be set before signing for Z value |
| **Outer contentType OID** | `1.2.840.113549.1.7.2` (pkcs7-signedData) | `1.2.156.10197.6.1.4.2.2` (GM/T 0010 signed data) — patched in DER after signing |
| **Inner eContentType OID** | `1.2.840.113549.1.7.1` (id-data) | `1.2.156.10197.6.1.4.2.1` (GM/T 0010 data) — set via `CMS_set1_eContentType()` before signing |
| **Signature algorithm OID** | `1.2.840.113549.1.1.10` (RSA-PSS) or `1.2.840.113549.1.1.11` (SHA-256 with RSA) | `1.2.156.10197.1.501` (SM2 with SM3) |

### OID Replacement Detail

The GM/T 0010 standard defines different OIDs for the CMS structure. Signatrust handles
this in two steps:

1. **Inner eContentType**: Set before signing via `CMS_set1_eContentType()` with the GM/T OID
   `1.2.156.10197.6.1.4.2.1`. This value is covered by the signature.

2. **Outer contentType**: OpenSSL always writes the standard pkcs7-signedData OID
   (`1.2.840.113549.1.7.2`) into the outer ContentInfo. After signing, Signatrust performs
   a DER-level byte patch to replace it with the GM/T OID `1.2.156.10197.6.1.4.2.2` and
   recalculates the SEQUENCE length field.

These OID changes are why standard `openssl cms -verify` cannot correctly parse an SM2-signed
CMS file — OpenSSL expects the standard PKCS#7 OIDs and will reject the GM/T OIDs.

### Why Standard OpenSSL Cannot Verify SM2 CMS

OpenSSL's `openssl cms -verify` fails for SM2 CMS signatures for two independent reasons:

1. **OID mismatch**: The outer contentType and inner eContentType use GM/T-specific OIDs
   that standard OpenSSL does not recognize. OpenSSL expects `pkcs7-signedData`
   (`1.2.840.113549.1.7.2`) and will fail to parse the CMS structure.

2. **Missing SM2 user ID**: Even if the OID issue were resolved, OpenSSL's CMS verification
   path does not call `EVP_PKEY_CTX_set1_id()`, so the SM2 Z value computed during
   verification will not match the one used during signing.

This is why **CmsVerify** (a GM/T-aware verification tool) is required to verify SM2-signed
CMS files from Signatrust.

---

## What SM2 Support Covers

Signatrust provides GM/T-compliant SM2 signing across the following operations.
When a key of type `sm2` is used, the signing process automatically handles the
SM2 user ID and Z value computation per GM/T 0003.2-2012. Non-SM2 keys (RSA, DSA)
are unaffected and continue to use the standard signing paths.

### 1. X.509 Certificate Signing

When generating an X.509 certificate with `key_type: sm2` and `digest_algorithm: sm3`,
Signatrust signs the certificate with the correct SM2 distinguishing identifier.
The resulting certificate can be verified by GM/T-compliant tools such as GmSSL.

### 2. CMS (Cryptographic Message Syntax) Signing

CMS signing with SM2 keys produces PKCS#7 / CMS SignedData structures signed
with SM2/SM3 and GM/T 0010-compliant OIDs, suitable for software package signing,
firmware signing, and other code-signing use cases.

CMS timestamp (TST) signing also supports SM2 keys, allowing an SM2-signed
timestamp token to be embedded into the CMS SignedData as an unsigned attribute.

### 3. CRL (Certificate Revocation List) Signing

CRL signing with SM2 keys produces a CRL whose signature includes the correct
SM2 Z value. The generated CRL can be verified using an SM2-capable OpenSSL build
or GmSSL. RSA/DSA CRL signing is unchanged.

---

## Verification

The SM2 signatures generated by Signatrust can be verified using CmsVerify,
which correctly handles the SM2 user ID and GM/T OIDs for GM/T-compliant
signature verification.

### Verifying an SM2-Signed CMS File

Prepare the following files:

a) Signer certificate chain: `sm2-ca-ica-chain.pem`
b) CRL chain: `sm2-ca-ica-chain.crl`
c) Original file: `sm2-test.txt`
d) Detached CMS signature: `sm2-test.txt.p7s`

Then verify with CmsVerify:

```powershell
.\CmsVerify.exe \
  -sig .\sm2-test.txt.p7s \
  -src .\sm2-test.txt \
  -crt .\sm2-ca-ica-chain.pem \
  -crl .\sm2-ca-ica-chain.crl
```

### Inspecting CRL Contents

To inspect the contents of a generated CRL:

```bash
openssl crl -in sm2_crl.pem -inform PEM -text -noout
```

---

## Supported Operations Matrix

| Operation | Key Type | Digest | GM/T Compliant |
|-----------|----------|--------|----------------|
| X.509 Certificate Sign | RSA / DSA | SHA-1/256/384/512 | N/A |
| X.509 Certificate Sign | SM2 | SM3 | ✅ |
| CMS Sign | RSA / DSA | SHA-1/256/384/512 | N/A |
| CMS Sign | SM2 | SM3 | ✅ |
| CMS Timestamp Sign | SM2 | SM3 | ✅ |
| CRL Sign | RSA / DSA | SHA-1/256/384/512 | N/A |
| CRL Sign | SM2 | SM3 | ✅ |

---

## How to Use SM2 Signing with Signatrust

### Generate an SM2 CA Key

Use the `signatrust-admin` binary to generate an SM2 Root CA key pair and self-signed certificate:

```bash
./signatrust-admin \
  --config /config/admin.toml \
  generate-keys \
  --key-type x509ca \
  --name sm2-root-ca \
  --description "SM2 Root CA for testing" \
  --param-key-type sm2 \
  --param-key-size 256 \
  --digest-algorithm sm3 \
  --param-x509-common-name "SM2 Root CA" \
  --param-x509-organization "MyOrg" \
  --param-x509-organizational-unit "Security" \
  --param-x509-locality "ShenZhen" \
  --param-x509-province-name "GuangDong" \
  --param-x509-country-name "CN" \
  --email admin@example.com \
  --visibility public
```

This calls the internal API endpoint `POST /api/v1/keys/` with the proper payload
populated from the CLI arguments.

### Generate a CMS Signature with an SM2 Key

Use the `signatrust-client` to sign a file with an SM2 X.509 EE key, producing a detached CMS
signature (PKCS#7):

```bash
./signatrust-client \
  --config /config/client.toml \
  add \
  --file-type p7s \
  --key-type x509 \
  --key-name my-sm2-key \
  --sign-type cms \
  --detached \
  origin.txt
```

Note: `--detached` is a boolean flag (creates a separate `.p7s` signature file).
`origin.txt` is the positional path argument pointing to the file to be signed.

### Generate CRL with an SM2 CA Key

A CRL can be generated for any CA or ICA key via the API. The returned CRL will be
signed with the SM2 key using the correct SM2 user ID, producing a GM/T-compliant signature.

```bash
curl -k --header "Authorization: <your-token>" \
  -X GET \
  https://<signatrust-host>:8080/api/v1/keys/sm2-root-ca/crl
```

---

## References

1. [GM/T 0003.2-2012 — SM2 Elliptic Curve Public Key Cryptography Algorithm Part 2: Digital Signature Algorithm](http://www.gmbz.org.cn/main/viewfile/2018011001400692565.html)
2. [GM/T 0003.3-2012 — SM2 Elliptic Curve Public Key Cryptography Algorithm Part 3: Key Exchange Protocol](http://www.gmbz.org.cn/main/viewfile/2018011001402567986.html)
3. [GM/T 0004-2012 — SM3 Cryptographic Hash Algorithm](http://www.gmbz.org.cn/main/viewfile/2018011002385367454.html)
4. [GM/T 0010 — SM2 Cryptographic Message Syntax (CMS) Specification](http://www.gmbz.org.cn/)
