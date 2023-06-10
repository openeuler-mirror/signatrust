# Support Private Certificate Authority in Signatrust

## Introduction
Now signatrust supports x509 keys, but it's all self-signed keys; we should consider supporting private certificate authority
because of the following reasons:
1. **Trust Establishment**: The CA acts as a trusted third party that vouches for the authenticity and integrity of the certificates
it issues. The CA's digital signature on the certificate provides assurance that the certificate has been issued by a trusted
source and has not been tampered with.
2. **Certificate Revocation**: In case a certificate needs to be revoked due to compromised private keys, change in status, or 
other reasons, the CA maintains a Certificate Revocation List (CRL). The CRL contains a list of revoked certificates, and
users(client) can check the CRL to ensure that a certificate has not been revoked before trusting it.
3. **Hierarchical Trust Model**: The CA operates within a hierarchical trust model, where multiple CAs form a chain of trust.
Higher-level CAs, known as root CAs, certify and sign the certificates of intermediate CAs, which, in turn, issue certificates
for end entities. This trust chain enables the establishment of trust from the root CAs down to the end-entity certificates.

## Design and Concept
In design, there would be three types of certificates, Root CA, Intermediate CA and End Entity. And we restrictively follow the 3-level hierarchical trust model in design.
```
            Root CA(validity period about 30 years)
                |
                |
        Intermediate CA(validity period about 10 years)
                |
                |
            End Entity(validity period about 3 year)
```
### Root CA
The root CA is the top-most CA in the hierarchy and is responsible for issuing certificates for intermediate CAs,
basically the root CA would be self-signed and will have a long validity period. We propose the profile for root CAs:
```shell
[ v3_ca ]
basicConstraints        = critical, CA:TRUE, pathlen:1
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer:always
keyUsage                = critical, cRLSign, digitalSignature, keyCertSign
nsCertType = objCA
nsComment = "Signatrust Root CA"
```
When generated, we can get the profile detail via inspecting certificate file:
```shell
  X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier:
                C4:16:4F:EC:B2:79:53:97:FC:D6:AA:CB:81:DF:5B:CD:BF:4B:56:A7
            X509v3 Authority Key Identifier:
                keyid:C4:16:4F:EC:B2:79:53:97:FC:D6:AA:CB:81:DF:5B:CD:BF:4B:56:A7
                DirName:/C=CN/ST=GuangDong/L=ShenZhen/O=RootCA/OU=RootCA/CN=RootCA/emailAddress=rootca@signatrust.com
                serial:40:80:BB:0B:9D:38:42:45:AC:0B:4A:BF:3F:85:E9:BE:A8:72:73:B0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            Netscape Cert Type:
                Object Signing CA
            Netscape Comment:
                Signatrust Root CA
```
### Intermediate CA
The intermediate CA is responsible for issuing end entities certificates. Considering we restrictively follow the 3-level hierarchical trust model, the profile for intermediate
CA would be:
```shell
[ v3_ica ]
basicConstraints        = critical, CA:TRUE, pathlen:0
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer:always
keyUsage                = critical, cRLSign, digitalSignature, keyCertSign
nsCertType = objCA
nsComment = "Signatrust Intermediate CA"
```
When generated, we can get the profile detail via inspecting certificate file:
```shell
  X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier:
                C4:16:4F:EC:B2:79:53:97:FC:D6:AA:CB:81:DF:5B:CD:BF:4B:56:A7
            X509v3 Authority Key Identifier:
                keyid:C4:16:4F:EC:B2:79:53:97:FC:D6:AA:CB:81:DF:5B:CD:BF:4B:56:A7
                DirName:/C=CN/ST=GuangDong/L=ShenZhen/O=IntermediateCA/OU=IntermediateCA/CN=IntermediateCA/emailAddress=intermidiateca@signatrust.com
                serial:40:80:BB:0B:9D:38:42:45:AC:0B:4A:BF:3F:85:E9:BE:A8:72:73:B0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            Netscape Cert Type:
                Object Signing CA
            Netscape Comment:
                Signatrust Intermediate CA
```
### End Entity (End Certificate)
The end entity is the entity that is being certified by the CA. And will be used for signature. The profile for
end entity would be:
```shell
[ v3_ee ]
basicConstraints        = critical, CA:FALSE
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer:always
keyUsage                = critical, digitalSignature, nonRepudiation
extendedKeyUsage        = codeSigning
nsCertType = objsign
nsComment = "Signatrust Sign Certificate"
```
When generated, we can get the profile detail via inspecting certificate file:
```shell
        Issuer: C = CN, ST = GuangDong, L = ShenZhen, O = IntermediateCA, OU = IntermediateCA, CN = IntermediateCA, emailAddress = intermidiateca@signatrust.com
        Validity
            Not Before: Jun 10 02:09:08 2023 GMT
            Not After : Jun  9 02:09:08 2024 GMT
        Subject: C = CN, ST = GuangDong, O = EndCertificate, OU = EndCertificate, CN = EndCertificate, emailAddress = endcertificat@signatrust.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    ......
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                90:EA:73:05:96:83:CE:6B:D2:47:59:83:C0:0B:BF:8D:B7:A3:8F:8A
            X509v3 Authority Key Identifier:
                keyid:08:D8:5F:D2:94:11:1A:52:AB:F0:D8:CA:42:45:44:BC:B4:D4:6A:38
                DirName:/C=CN/ST=GuangDong/L=ShenZhen/O=IntermediateCA/OU=IntermediateCA/CN=IntermediateCA/emailAddress=intermidiateca@signatrust.com
                serial:6B:A3:88:37:5E:6D:D6:89:31:04:D1:D2:5D:0E:D2:4F:F0:34:D3:17
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation
            X509v3 Extended Key Usage:
                Code Signing
            Netscape Cert Type:
                Object Signing
            Netscape Comment:
                Signatrust Sign Certificate
```
### Certificate Revocation List
one of the benefits we can get from introducing private CA is about the certificate revocation list; we need both support to revoke intermediate CA and end entity certificate.
the CRL content would be updated every **7** days in design, and the generated certificates would append the CRL Distribution Endpoint in X509 extension as well:
```shell
X509v3 CRL Distribution Points:
            Full Name:
              URI:https://signatrust.osinfra.cn/api/v1/keys/<ca-or-intermediate-ca-id>/crl
```
### Others
Since the CAs are usually public for certificates and CRLs download,
we don't support generating personal CA and ICA for now.

## Implementation
### Model
Within this proposal, now the DateKey object would have new optional status:
```rust
#[derive(Debug, Clone, Default, PartialEq)]
pub enum KeyState {
    Enabled,
    #[default]
    Disabled,
    PendingRevoke,  //new status
    Revoked,        //new status
    PendingDelete,
    Deleted
}
```
### Database
1. Since signatrust supports both x509 and openPGP keys, and we already have the column `key_type` to indicate the key type
we can utilize this column and introduce `ca` and `intermediate_ca` for this change:
```rust
#[derive(Debug, Clone)]
pub enum KeyType {
    OpenPGP,
    X509CA,  //new type
    X509ICA, //new type
    X509EE,  //renamed from X509
}
```
Considering we have not officially released our first version,
we should drop all existing X509 keys in the database because they don't follow our
new design.

2. In order to support the hierarchical structure introduced by CAs, we should add a new column named `parent_id` for datakey
table, it's only useful for `X509EE` and `X509ICA`.
```sql
ALTER TABLE data_key ADD parent_id INT AFTER `key_type`;
```

3. We need to introduce two new tables to store the CRL content and revoked keys, the tables would be:
```sql
CREATE TABLE x509_crl_content (
                       id INT AUTO_INCREMENT,                       
                       create_at DATETIME,
                       update_at DATETIME,
                       data TEXT NOT NULL,
                       PRIMARY KEY(id),                    
);
CREATE TABLE x509_crl_revoked (
                      id INT AUTO_INCREMENT,
                      ca_id INT NOT NULL,
                      key_id INT NOT NULL,
                      create_at DATETIME,
                      FOREIGN KEY (ca_id) REFERENCES data_key(id),
                      FOREIGN KEY (key_id) REFERENCES data_key(id),
                      UNIQUE KEY `unique_ca_and_key` (`ca_id`,`key_id`)                   
                      PRIMARY KEY(id),
);
```
### Control Server
#### Generate Keys
Now when generating keys, the `parent_id` can be passed in the request body, it only works for `X509ICA` and `X509EE`:
```shell
{
    "name": "test-pgp",
    "description": "hello world",
    "key_type": "pgp",
    "parent_id": "refer to CA or ICA key"  #New attribute
    "visibility": "public",
    "attributes": {
    "digest_algorithm": "sha2_256",
    "key_type": "rsa",
    "key_length": "2048",
    "email": "test@openeuler.org",
    "passphrase": "password"
    },
    "create_at": "2023-04-12 22:10:57+08:00",
    "expire_at": "2024-05-12 22:10:57+08:00"
}
```
For x509 key generation, currently we use x509 builder to create the private key as well as certificate
at the same time; within this proposal, the generation process will differ based on different key types:
```shell
1. RoootCA: 
    a. Generate private key
    b. Generate self signed certificate
    c. Generate CRL within empty revoked list
2. IntermediateCA:
    a. Generate private key
    b. Generate CSR
    c. Sign CSR with RootCA
    c. Generate CRL within empty revoked list
3. EndEntity:
    a. Generate private key
    b. Generate CSR
    c. Sign CSR with IntermediateCA    
```
#### Export Keys Content
We need to introduce a new endpoint to check the CRL status of a specific CA or intermediate CA, considering we already 
have the endpoint to export keys, we should update the export API to match the changes, the endpoint currently we have:
```shell
  POST -H 'Authorization: XXXX' /api/v1/keys/<key-id>/export
  Response in JSON:
  {
  "certificate": "string",
  "public_key": "string"
  }
```
The endpoint will be split into three individual and explicit endpoints:

a. Get public key, it's only valid for `openPGP` keys and will get armored public key:
```shell
  GET -H 'Authorization: XXXX' /api/v1/keys/<key-id>/public_key
  Response in TEXT:
    -----BEGIN PGP PUBLIC KEY BLOCK-----

    ...key content...
  -----END PGP PUBLIC KEY BLOCK-----
```
b. Get certificate, the endpoint only valid for `X509CA`, `X509ICA` and `X509EE` keys and will get PEM encoded certificate:
```shell
  GET -H 'Authorization: XXXX' /api/v1/keys/<key-id>/certificate
  Response in TEXT:
    -----BEGIN CERTIFICATE-----

    ...certificate content...
  -----END CERTIFICATE-----
```
c. Get CRL content, the endpoint is **public** and only valid for `X509CA` and `X509ICA` keys and will get the PEM encoded CRL:
```shell
  GET /api/v1/keys/<key-id>/crl
  Response in TEXT:
    -----BEGIN X509 CRL-----

    ...crl content...
  -----END X509 CRL-----
```
#### Key operations
We support request/cancel delete public keys via APIs as follows:
```shell
POST /api/v1/keys/<key-id>/request_delete
POST /api/v1/keys/<key-id>/cancel_delete
```
In order to support revoke certificates, we need to introduce a new group of APIs to revoke certificates, considering revoke and
delete are belong to key operations, we propose to update those APIs in the following:
```shell
POST /api/v1/keys/<key-id>/action/request_delete
POST /api/v1/keys/<key-id>/action/cancel_delete
POST /api/v1/keys/<key-id>/action/request_revoke
POST /api/v1/keys/<key-id>/action/cancel_revoke
```
#### CRL generation detail
We use rust-openssl to handle the x509 related operations, but the rust-openssl library currently doesn't support CRL
generation, we need to utilize the openssl C library and FFI to generate CRLs; ChatGPT generates the code below for demonstration:
```cpp
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int main() {
    X509_CRL *crl = X509_CRL_new();

    // Load the CA certificate and private key
    const char *caCertFile = "ca_certificate.pem";
    const char *caKeyFile = "ca_private_key.pem";

    X509 *caCert = NULL;
    EVP_PKEY *caKey = NULL;

    FILE *file = fopen(caCertFile, "r");
    if (file) {
        caCert = PEM_read_X509(file, NULL, NULL, NULL);
        fclose(file);
    }

    file = fopen(caKeyFile, "r");
    if (file) {
        caKey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
        fclose(file);
    }

    if (!caCert || !caKey) {
        fprintf(stderr, "Failed to load CA certificate or private key\n");
        return 1;
    }

    // Set the issuer for the CRL
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert));

    // Set the last update and next update dates for the CRL
    X509_gmtime_adj(X509_CRL_get_lastUpdate(crl), 0);
    X509_gmtime_adj(X509_CRL_get_nextUpdate(crl), 60 * 60 * 24 * 30); // 30 days

    // Create a CRL entry and add it to the CRL
    X509_REVOKED *revoked = X509_REVOKED_new();
    ASN1_INTEGER_set(X509_REVOKED_get0_serialNumber(revoked), 123); // Set the serial number of the revoked certificate

    // Set the revocation date (optional)
    ASN1_TIME_set(X509_REVOKED_get0_revocationDate(revoked), time(NULL));

    // Add the CRL entry to the CRL
    X509_CRL_add0_revoked(crl, revoked);

    // Sign the CRL with the CA private key
    if (!X509_CRL_sign(crl, caKey, EVP_sha256())) {
        fprintf(stderr, "Failed to sign the CRL\n");
        return 1;
    }

    // Save the CRL to a file
    const char *crlFile = "crl.pem";
    file = fopen(crlFile, "w");
    if (file) {
        PEM_write_X509_CRL(file, crl);
        fclose(file);
        printf("CRL generated and saved to: %s\n", crlFile);
    } else {
        fprintf(stderr, "Failed to save the CRL\n");
        return 1;
    }

    // Clean up
    X509_CRL_free(crl);
    X509_free(caCert);
    EVP_PKEY_free(caKey);

    return 0;
}
```
**Alternative**: Add CRL generation support in the rust-openssl library is also an option, but it's not a trivial task.

CRL update will be performed by the control server periodically, for every CA and ICA it's every 7 days, we will check
the `update_at` column of the `x509_crl_content` table and compare it with the current time. The `x509_crl_revoked` will be updated based on two conditions:
1. Add: when a certificate is revoked, and it's signed by the corresponding CA/ICA.
2. Remove: when a certificate is deleted.
