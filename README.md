# Signatrust
[![RepoSize](https://img.shields.io/github/repo-size/TommyLike/signatrust)](https://gitee.com/openeuler/signatrust)
[![Clippy check](https://github.com/TommyLike/signatrust/actions/workflows/build.yml/badge.svg)](https://github.com/TommyLike/signatrust/actions/workflows/build.yml)

Signatrust offers a highly secure, async and efficient solution for signing Linux packages and binaries using Rust. Our unified
platform ensures streamlined operations and a high throughput for all signing requests.

# Background

Signing packages and binaries for a Linux distribution is essential in many use cases. Typically, PGP is used for RPM
packages, ISO checksums, AppImages, and repository metadata. X509 certificates, on the other hand, are used to cover the
cases of kernel modules and EFI. While there are several projects and scripts already in use within the community, 
they are often limited to CI/CD environments, and the management and security of private keys are not always covered.

We have observed several projects aiming to address these challenges.
1. [**OBS sign**](https://github.com/openSUSE/obs-sign): Developed by openSUSE, obs-sign is a widely used Linux distro
   packaging system, including [OBS](https://build.opensuse.org/) and [COPR](https://copr.fedorainfracloud.org/). The
   solution provides a comprehensive server-client model for massive signing tasks in a production environment. 
   However, one of the challenges faced by the system is the difficulty in replicating instances to increase throughput.
   Additionally, the system is also plagued by security and management concerns, as PGP is located on the server disk directly.
2. [**sbsigntools**](https://github.com/phrack/sbsigntools) This is a fork version of official sbsigntools which can store
    certificates & key in AWS CloudHSM and targets for UEFI signing.
3. other tools.

# Features

**Signatrust**, stands for `Signature + Trust + Rust` is a rust project that can provide a unified solution for all the challenges:
 
1. **E2E security design**: Our end-to-end security design prioritizes the protection of sensitive data, such as keys and
   certificates, by transparently encrypting them with external KMS providers, like CloudHSM or Huawei KMS, before storing them in the
   database. Additionally, we have eliminated the need to transfer private keys to the client for local sign operations,
   opting instead to deliver content to the sign server and perform signature calculations directly in memory. Furthermore,
   all memory keys are zeroed out when dropped to protect against leaks to swap and core dump. Currently, mutual TLS is required
   for communication between the client and server, with future upgrades planned to integrate with the SPIFF&SPIRE ecosystem.

2. **High throughput**: To ensure high throughput, we have split the control server and data server and made it easy to
   replicate the data server. We have also made several performance enhancements, such as utilizing gRPC stream, client
   round-robin, memory cache, and async tasks to increase single-instance performance.

3. **Complete binaries support**:
   1. RPM/SRPM signature.
   2. Detached PGP signature including ISO checksum and repo metadata.
   3. Kernel module signature.
   4. EFI(todo).
   5. Container Image(todo).
   6. WSL Image(todo).
   7. AppImage(todo).

4. **User-friendly key management**: Signatrust offers a user-friendly, standalone interface for managing sensitive keys,
   which can be seamlessly integrated with external account systems using the OpenID Connect (OIDC) protocol. Administrators
   have the ability to generate, import, export, and delete keys through this intuitive interface.

# System Context
![System Context](./docs/images/System%20Context.png)
# Performance
According to our performance tests, Signatrust outperformed Obs Sign(with pgp agent backend) by a significant margin in a concurrent test environment:

1. **Server**: Single instance with limited resources of 8 CPUs and 8GB RAM.
2. **Clients**: 1/2/4 instances, each with limited resources of 8 CPUs and 10GB RAM.
3. **Task per client**: Signing the entire set of RPM packages in the [openEuler21.09 source](https://archives.openeuler.openatom.cn/openEuler-21.09/source/Packages/), which amounted to 4168 packages and 18GB in total.
4. **Concurrency per client**: 50.
5. **NOTE**: obs sign only support sign a single file, in order to support concurrent operations, we wrap the `obs-sign` command with golang `goroutines` or python `multiprocessing`.

![Performance](./docs/images/sign%20performance.png)

Based on these test results, it appears that Signatrust is a more efficient and effective solution for signing RPM packages, it's also worth noting that the performance issue of obs sign is mainly due to the gpg's agent implementation.

# Backend Security
In order to support different levels of backend security, signatrust supports different kinds of sign backend, `memory` backend is the default one which will provide better performance
while all sensitive data are stored decrypted in memory. the configuration would be like:
```shell
[sign-backend]
type = "memory"
[memory.kms-provider]
type = ""
kms_id = ""
endpoint = ""
project_name = ""
project_id = ""
username = ""
password = ""
domain=""
[memory.encryption-engine]
keep_in_days = 180
algorithm = "aes256gsm"
```

# Quick Start Guide
## Local development
When using memory backend, to ensure the security of sensitive data, Signatrust requires an external KMS system for encryption and decryption. However,
to run the system locally for development purposes, you will need to configure a **dummy** KMS provider
```shell
[kms-provider]
type = "dummy"
```
Additionally, we have provided a script to set up the MySQL database in a Docker environment. To use the script, you will
need to install the Docker server, the MySQL binary, and the [Sqlx binary](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#enable-building-in-offline-mode-with-query).
Once you have these installed, simply run the
command below:
```shell
make db
```
Run these command correspondingly to build binary or launching server:
```shell
# build binary
cargo build --bin control-server/data-server/client
# running command
RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/<binary> --config <config-file-path>
```


# Contribute
