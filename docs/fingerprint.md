# How to identify the fingerprint of datakey
Signatrust will keep the fingerprint of datakey in database as following:
```json
{
        "id": 2,
        "name": "default-x509",
        "email": "tommylikehu@gmail.com",
        "description": "used for test purpose only",
        "user": 1,
        "attributes": {
            "common_name": "Infra",
            "country_name": "CN",
            "create_at": "2023-04-20 07:00:57.695607 UTC",
            "digest_algorithm": "sha2_256",
            "expire_at": "2023-05-20 07:00:57.695607 UTC",
            "key_length": "2048",
            "key_type": "rsa",
            "locality": "ShenZhen",
            "name": "default-x509",
            "organization": "openEuler",
            "organizational_unit": "Infra",
            "province_name": "GuangDong"
        },
        "key_type": "x509",
        "fingerprint": "94195AD20235DF8535E3E7DDA7188C6296323A8E",
        "create_at": "2023-04-20 07:00:58 UTC",
        "expire_at": "2023-05-20 07:00:58 UTC",
        "key_state": "enabled"
    }
```
Once you exported the certificate or public key, you may use the commands below to verify whether the fingerprint matches:
## openPGP
```shell
➜  codes gpg --import <public-key>.file
gpg: key 524817AA41D02F6E: public key "default-pgp <infra@openeuler.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
➜  codes gpg --list-keys
/Users/tommylike/.gnupg/pubring.kbx
-----------------------------------
pub   rsa2048 2023-04-20 [SC]
      B96554CCFB546583ACA3D88B524817AA41D02F6E
uid           [ unknown] default-pgp <infra@openeuler.org>
```
## x509
```shell
openssl x509 -noout -fingerprint -sha1 -inform pem -in <certificate>.file
SHA1 Fingerprint=94:19:5A:D2:02:35:DF:85:35:E3:E7:DD:A7:18:8C:62:96:32:3A:8E
```
