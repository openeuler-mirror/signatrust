# prerequisite
- create a x509 key in data server if you do not have one
    ```bash
    curl -X 'POST' \
    'http://10.0.0.139:8080/api/v1/keys/' \
    -H 'accept: application/json' \
    -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc' \
    -H 'Content-Type: application/json' \
    -d '{
    "attributes": {
        "digest_algorithm": "sha2_256",
        "key_length": "4096",
        "key_type": "rsa",
        "common_name": "EFI signer",
        "country_name": "CN",
        "locality": "Chengdu",
        "organization": "openEuler",
        "organizational_unit": "infra",
        "province_name": "Sichuan"
    },
    "description": "a test x509 key pair",
    "expire_at": "2024-05-12 22:10:57+08:00",
    "key_type": "x509",
    "name": "my-x509"
    }'
    ```
- export the x509 certificate into PEM format
    - get the key id
    ```
    curl -X 'GET' \
        'http://10.0.0.139:8080/api/v1/keys/' \
        -H 'accept: application/json' \
        -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc'
    ```
    
    ```
    [
        {
            "id": 5,
            "name": "my-x509",
            "email": "tommylikehu@gmail.com",
            "description": "a test x509 key pair",
            "user": 1,
            "attributes": {
            "common_name": "EFI signer",
            "country_name": "CN",
            "create_at": "2023-05-04 09:24:01.488589752 UTC",
            "digest_algorithm": "sha2_256",
            "expire_at": "2024-05-12 22:10:57+08:00",
            "key_length": "4096",
            "key_type": "rsa",
            "locality": "Chengdu",
            "name": "my-x509",
            "organization": "openEuler",
            "organizational_unit": "infra",
            "province_name": "Sichuan"
            },
            "key_type": "x509",
            "fingerprint": "2A8853F8411F4B243FB424F90B2541D7AE5AF8C9",
            "create_at": "2023-05-04 09:24:01 UTC",
            "expire_at": "2024-05-12 14:10:57 UTC",
            "key_state": "disabled"
        }
    ]
    ```
    - enable the key
    ```
    curl -X 'POST' \
        'http://10.0.0.139:8080/api/v1/keys/5/enable' \
        -H 'accept: */*' \
        -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc' \
        -d ''
    ```
    - get key certificate by id
    ```
    curl -X 'POST' \
        'http://10.0.0.139:8080/api/v1/keys/5/export' \
        -H 'accept: application/json' \
        -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc' \
        -d ''
    ```
    
    ```
    {
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5xd/p5oqJBpfZlU3WmdK\nfFS7ZwdUAssXyQDxXTUHe4LoZ3imFcpQed41Yu/rBxKQzLtSmHkpZ9Bw6bDplQrv\nuTYaeLtfiDUAa2kZVCBzDnFFx4J6v5jkoC4i1SYeGPtEW4D5m8xn8G5aCslEnpvL\nYQ1oXi14vORHzuC7uMfkDh+/JTOYkRw083lFjZEXEh5Jjf0mZNLN9PhBzOCzDalA\nBGhpcOATtkKxEDtXcyVNJEqf8sfpz7FKNpNBNIKb3EZX168OFp+yeK3pd1dhAc+F\nFkmZmwN+Qb065znGfdltxh9F75yPB1CeJEedirTVj/QvALSSkFlKS9TFgRgh7T2z\nKlj7Bw+fC9cXJCjUevgnl6pFvrEqVTu+topmWcEPKPJiI1xPVtFcRjEEgTnkTRcp\nfoDxKngh3oj1+5szBXwMKnnk1wc7TK8zqTcxEbLeSkiTxU5ptWasnkhqHoJyzO9w\njc7qasvSKxUou0+VD0W/EID4KkLgomkwiFUGFeYstpbpiC0FJS3M/JOLIibPRXK5\n4YMxw23bHqDP4J02J6NdmrLLiKXaRy2MCcxlovckswqYz/4xjT9ye9dc8DMengLn\n5+iDpxzCdBjvTdGXejY3gTvQ68JKz6TznBcz+ooh6K/bH950Kr3JDwZkCTpuZKQn\nXSWZhXVN1sHbZJn7IneyPKkCAwEAAQ==\n-----END PUBLIC KEY-----\n",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIIFTTCCAzWgAwIBAgIBADANBgkqhkiG9w0BAQ4FADBqMRMwEQYDVQQDDApFRkkg\nc2lnbmVyMQ4wDAYDVQQLDAVpbmZyYTESMBAGA1UECgwJb3BlbkV1bGVyMRAwDgYD\nVQQHDAdDaGVuZ2R1MRAwDgYDVQQIDAdTaWNodWFuMQswCQYDVQQGEwJDTjAeFw0y\nMzA1MDQwOTI0MDJaFw0yNDA1MTIwOTI0MDJaMGoxEzARBgNVBAMMCkVGSSBzaWdu\nZXIxDjAMBgNVBAsMBWluZnJhMRIwEAYDVQQKDAlvcGVuRXVsZXIxEDAOBgNVBAcM\nB0NoZW5nZHUxEDAOBgNVBAgMB1NpY2h1YW4xCzAJBgNVBAYTAkNOMIICIjANBgkq\nhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5xd/p5oqJBpfZlU3WmdKfFS7ZwdUAssX\nyQDxXTUHe4LoZ3imFcpQed41Yu/rBxKQzLtSmHkpZ9Bw6bDplQrvuTYaeLtfiDUA\na2kZVCBzDnFFx4J6v5jkoC4i1SYeGPtEW4D5m8xn8G5aCslEnpvLYQ1oXi14vORH\nzuC7uMfkDh+/JTOYkRw083lFjZEXEh5Jjf0mZNLN9PhBzOCzDalABGhpcOATtkKx\nEDtXcyVNJEqf8sfpz7FKNpNBNIKb3EZX168OFp+yeK3pd1dhAc+FFkmZmwN+Qb06\n5znGfdltxh9F75yPB1CeJEedirTVj/QvALSSkFlKS9TFgRgh7T2zKlj7Bw+fC9cX\nJCjUevgnl6pFvrEqVTu+topmWcEPKPJiI1xPVtFcRjEEgTnkTRcpfoDxKngh3oj1\n+5szBXwMKnnk1wc7TK8zqTcxEbLeSkiTxU5ptWasnkhqHoJyzO9wjc7qasvSKxUo\nu0+VD0W/EID4KkLgomkwiFUGFeYstpbpiC0FJS3M/JOLIibPRXK54YMxw23bHqDP\n4J02J6NdmrLLiKXaRy2MCcxlovckswqYz/4xjT9ye9dc8DMengLn5+iDpxzCdBjv\nTdGXejY3gTvQ68JKz6TznBcz+ooh6K/bH950Kr3JDwZkCTpuZKQnXSWZhXVN1sHb\nZJn7IneyPKkCAwEAATANBgkqhkiG9w0BAQ4FAAOCAgEAObCqV91IlCpELDyDdVm1\nyc2xYlwbleeamI4lRQ9dbUxJgmoEvHrigTy6+QddTWTvq1ClB66FFr4CmP4R44ew\nOOnkUhdynZy23+qR0f9RKLpM/bQFzFAJJGkjVaz9OA0nD6lbGHxlljB0palnpeQN\nbXT42I9+pKQ+jmLQeUM5G2OYmEiOeATh5fDG50/Mi71vcjJBpcqoGy0eJQnbpTLr\nH3q3TjffpI4VmB4XZCdv4M8mTeZrT9fz40/tknUpGrD1ZDnOeAEX54KxCDhMpDPd\nJzhZAsd1zT23gEVyiJzXjnJb+ooCjLskFgIDRwim4/P8oMrmYJLC3PTf33AHiIsZ\nxka4Io7xNc58pAZPef1MLMRRxvZL2sHocZ1u3imPW0/9NdICLLCw+kCuXXZyjzsb\n3AhivrkA4pHuEakYcKZ7m4cbEdhn+A8VH+cZ6F8dOt683a3h/1KMUA9RgbmkRfOY\nBd0ifVYZNlL2P7+aRB5MYYdjvtFTjvuYnaiCsk0rfKeFcLRcdqH/LwsnmYI58ak+\noBg1q7IwUKiMMQJXv80sYpulMVNf4yogMwxuDb8aKSMoYYHqwpc/APxpxxIYqals\njm/mYiBzbODW1CkAXzFKlDxwbOHbYE/BjtQka4UKGoJbmhSRae9axKxj1bBj4Vud\ntTN6jZmbEb/Bmclsaooig1g=\n-----END CERTIFICATE-----\n"
    }
    ```
    - save the `certificate` filed as a PEM file
    ```
    $ echo "-----BEGIN CERTIFICATE-----\nMIIFTTCCAzWgAwIBAgIBADANBgkqhkiG9w0BAQ4FADBqMRMwEQYDVQQDDApFRkkg\nc2lnbmVyMQ4wDAYDVQQLDAVpbmZyYTESMBAGA1UECgwJb3BlbkV1bGVyMRAwDgYD\nVQQHDAdDaGVuZ2R1MRAwDgYDVQQIDAdTaWNodWFuMQswCQYDVQQGEwJDTjAeFw0y\nMzA1MDQwOTI0MDJaFw0yNDA1MTIwOTI0MDJaMGoxEzARBgNVBAMMCkVGSSBzaWdu\nZXIxDjAMBgNVBAsMBWluZnJhMRIwEAYDVQQKDAlvcGVuRXVsZXIxEDAOBgNVBAcM\nB0NoZW5nZHUxEDAOBgNVBAgMB1NpY2h1YW4xCzAJBgNVBAYTAkNOMIICIjANBgkq\nhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5xd/p5oqJBpfZlU3WmdKfFS7ZwdUAssX\nyQDxXTUHe4LoZ3imFcpQed41Yu/rBxKQzLtSmHkpZ9Bw6bDplQrvuTYaeLtfiDUA\na2kZVCBzDnFFx4J6v5jkoC4i1SYeGPtEW4D5m8xn8G5aCslEnpvLYQ1oXi14vORH\nzuC7uMfkDh+/JTOYkRw083lFjZEXEh5Jjf0mZNLN9PhBzOCzDalABGhpcOATtkKx\nEDtXcyVNJEqf8sfpz7FKNpNBNIKb3EZX168OFp+yeK3pd1dhAc+FFkmZmwN+Qb06\n5znGfdltxh9F75yPB1CeJEedirTVj/QvALSSkFlKS9TFgRgh7T2zKlj7Bw+fC9cX\nJCjUevgnl6pFvrEqVTu+topmWcEPKPJiI1xPVtFcRjEEgTnkTRcpfoDxKngh3oj1\n+5szBXwMKnnk1wc7TK8zqTcxEbLeSkiTxU5ptWasnkhqHoJyzO9wjc7qasvSKxUo\nu0+VD0W/EID4KkLgomkwiFUGFeYstpbpiC0FJS3M/JOLIibPRXK54YMxw23bHqDP\n4J02J6NdmrLLiKXaRy2MCcxlovckswqYz/4xjT9ye9dc8DMengLn5+iDpxzCdBjv\nTdGXejY3gTvQ68JKz6TznBcz+ooh6K/bH950Kr3JDwZkCTpuZKQnXSWZhXVN1sHb\nZJn7IneyPKkCAwEAATANBgkqhkiG9w0BAQ4FAAOCAgEAObCqV91IlCpELDyDdVm1\nyc2xYlwbleeamI4lRQ9dbUxJgmoEvHrigTy6+QddTWTvq1ClB66FFr4CmP4R44ew\nOOnkUhdynZy23+qR0f9RKLpM/bQFzFAJJGkjVaz9OA0nD6lbGHxlljB0palnpeQN\nbXT42I9+pKQ+jmLQeUM5G2OYmEiOeATh5fDG50/Mi71vcjJBpcqoGy0eJQnbpTLr\nH3q3TjffpI4VmB4XZCdv4M8mTeZrT9fz40/tknUpGrD1ZDnOeAEX54KxCDhMpDPd\nJzhZAsd1zT23gEVyiJzXjnJb+ooCjLskFgIDRwim4/P8oMrmYJLC3PTf33AHiIsZ\nxka4Io7xNc58pAZPef1MLMRRxvZL2sHocZ1u3imPW0/9NdICLLCw+kCuXXZyjzsb\n3AhivrkA4pHuEakYcKZ7m4cbEdhn+A8VH+cZ6F8dOt683a3h/1KMUA9RgbmkRfOY\nBd0ifVYZNlL2P7+aRB5MYYdjvtFTjvuYnaiCsk0rfKeFcLRcdqH/LwsnmYI58ak+\noBg1q7IwUKiMMQJXv80sYpulMVNf4yogMwxuDb8aKSMoYYHqwpc/APxpxxIYqals\njm/mYiBzbODW1CkAXzFKlDxwbOHbYE/BjtQka4UKGoJbmhSRae9axKxj1bBj4Vud\ntTN6jZmbEb/Bmclsaooig1g=\n-----END CERTIFICATE-----\n" | sed -E 's|\\\n|\n|g' > certificate.pem
    $ cat certificate
    -----BEGIN CERTIFICATE-----
    MIIFTTCCAzWgAwIBAgIBADANBgkqhkiG9w0BAQ4FADBqMRMwEQYDVQQDDApFRkkg
    c2lnbmVyMQ4wDAYDVQQLDAVpbmZyYTESMBAGA1UECgwJb3BlbkV1bGVyMRAwDgYD
    VQQHDAdDaGVuZ2R1MRAwDgYDVQQIDAdTaWNodWFuMQswCQYDVQQGEwJDTjAeFw0y
    MzA1MDQwOTI0MDJaFw0yNDA1MTIwOTI0MDJaMGoxEzARBgNVBAMMCkVGSSBzaWdu
    ZXIxDjAMBgNVBAsMBWluZnJhMRIwEAYDVQQKDAlvcGVuRXVsZXIxEDAOBgNVBAcM
    B0NoZW5nZHUxEDAOBgNVBAgMB1NpY2h1YW4xCzAJBgNVBAYTAkNOMIICIjANBgkq
    hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5xd/p5oqJBpfZlU3WmdKfFS7ZwdUAssX
    yQDxXTUHe4LoZ3imFcpQed41Yu/rBxKQzLtSmHkpZ9Bw6bDplQrvuTYaeLtfiDUA
    a2kZVCBzDnFFx4J6v5jkoC4i1SYeGPtEW4D5m8xn8G5aCslEnpvLYQ1oXi14vORH
    zuC7uMfkDh+/JTOYkRw083lFjZEXEh5Jjf0mZNLN9PhBzOCzDalABGhpcOATtkKx
    EDtXcyVNJEqf8sfpz7FKNpNBNIKb3EZX168OFp+yeK3pd1dhAc+FFkmZmwN+Qb06
    5znGfdltxh9F75yPB1CeJEedirTVj/QvALSSkFlKS9TFgRgh7T2zKlj7Bw+fC9cX
    JCjUevgnl6pFvrEqVTu+topmWcEPKPJiI1xPVtFcRjEEgTnkTRcpfoDxKngh3oj1
    +5szBXwMKnnk1wc7TK8zqTcxEbLeSkiTxU5ptWasnkhqHoJyzO9wjc7qasvSKxUo
    u0+VD0W/EID4KkLgomkwiFUGFeYstpbpiC0FJS3M/JOLIibPRXK54YMxw23bHqDP
    4J02J6NdmrLLiKXaRy2MCcxlovckswqYz/4xjT9ye9dc8DMengLn5+iDpxzCdBjv
    TdGXejY3gTvQ68JKz6TznBcz+ooh6K/bH950Kr3JDwZkCTpuZKQnXSWZhXVN1sHb
    ZJn7IneyPKkCAwEAATANBgkqhkiG9w0BAQ4FAAOCAgEAObCqV91IlCpELDyDdVm1
    yc2xYlwbleeamI4lRQ9dbUxJgmoEvHrigTy6+QddTWTvq1ClB66FFr4CmP4R44ew
    OOnkUhdynZy23+qR0f9RKLpM/bQFzFAJJGkjVaz9OA0nD6lbGHxlljB0palnpeQN
    bXT42I9+pKQ+jmLQeUM5G2OYmEiOeATh5fDG50/Mi71vcjJBpcqoGy0eJQnbpTLr
    H3q3TjffpI4VmB4XZCdv4M8mTeZrT9fz40/tknUpGrD1ZDnOeAEX54KxCDhMpDPd
    JzhZAsd1zT23gEVyiJzXjnJb+ooCjLskFgIDRwim4/P8oMrmYJLC3PTf33AHiIsZ
    xka4Io7xNc58pAZPef1MLMRRxvZL2sHocZ1u3imPW0/9NdICLLCw+kCuXXZyjzsb
    3AhivrkA4pHuEakYcKZ7m4cbEdhn+A8VH+cZ6F8dOt683a3h/1KMUA9RgbmkRfOY
    Bd0ifVYZNlL2P7+aRB5MYYdjvtFTjvuYnaiCsk0rfKeFcLRcdqH/LwsnmYI58ak+
    oBg1q7IwUKiMMQJXv80sYpulMVNf4yogMwxuDb8aKSMoYYHqwpc/APxpxxIYqals
    jm/mYiBzbODW1CkAXzFKlDxwbOHbYE/BjtQka4UKGoJbmhSRae9axKxj1bBj4Vud
    tTN6jZmbEb/Bmclsaooig1g=
    -----END CERTIFICATE-----
    ```

# sign a EFI file
```
RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/client -c client.toml add --file-type efi-image --key-type x509 --key-name my-x509 --sign-type authenticode  `pwd`/shimx64.efi
```

# verify the EFI file
- first we should compile `sbsigntools`
```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git
cd sbsigntools
git submodule init && git submodule update
make
```
- verify the signed EFI image using the certificate we exported
```
$ src/sbverify `pwd`/shimx64.efi --cert certificate
warning: data remaining[827688 vs 953240]: gaps between PE/COFF sections?
Signature verification OK
```