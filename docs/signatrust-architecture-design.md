# Signatrust 软件架构设计说明书

## 目录

1. [简介](#1-简介)
2. [概念模型](#2-概念模型)
3. [架构目标与质量属性](#3-架构目标与质量属性)
4. [架构原则](#4-架构原则)
5. [上下文与用例模型](#5-上下文与用例模型)
6. [关键架构决策（ADR）](#6-关键架构决策adr)
7. [逻辑架构](#7-逻辑架构)
8. [运行时视图](#8-运行时视图)
9. [数据模型](#9-数据模型)
10. [实现架构与部署模型](#10-实现架构与部署模型)
11. [横切关注点](#11-横切关注点)
12. [安全 / 韧性 / 可靠性 / 可用性设计](#12-安全--韧性--可靠性--可用性设计)
13. [附录](#13-附录)

---

## 1. 简介

### 1.1 目的

本文档为 openEuler 社区的 **Signatrust** 签名服务系统提供完整的软件架构设计说明。文档覆盖系统的概念模型、架构目标与原则、逻辑架构、运行时视图、数据模型、部署模型，以及安全 / 韧性 / 可靠性 / 可用性设计，为开发团队、运维团队及社区贡献者提供统一的技术参考。

**Signatrust**（**Sign**ature + Trust + **Rust**）是一个使用 Rust 语言开发的高安全、异步、高吞吐的 Linux 软件包与二进制文件签名服务平台。其核心价值主张：

- **端到端安全**：通过外部 KMS 加密密钥、二级 AES 加密、mTLS 传输加密、内存签名计算、密钥零化释放，构建完整的密钥保护链路。
- **高吞吐**：控制面 / 数据面分离设计，数据面可水平扩展，采用 gRPC 流式传输处理大文件。
- **多格式统一**：单一平台覆盖 PGP（RPM/SRPM/ISO checksum/仓库元数据）、X509（内核模块 / EFI / IMA）、CMS/PKCS#7（含国密 SM2/SM3）等多种签名场景。

### 1.2 范围

**覆盖范围**：

- Signatrust 系统的完整软件架构：概念模型、逻辑架构、运行时视图、数据模型、部署架构。
- 控制面（control-server、Web UI）与数据面（data-server、client）的架构设计。
- 与外部系统的集成边界（KMS、OIDC、MySQL、Redis、Kafka）。
- 安全架构：密钥保护链路、认证授权、传输安全、威胁模型。
- 生产部署模型：基于 openEuler 基础设施的 Kubernetes 部署配置。

**不覆盖范围**：

- 完整的 API 参数级规范（参见运行时生成的 Swagger/OpenAPI 文档，本文档第 7.4 节给出接口契约概览）。
- 各签名格式的操作手册（参见 `docs/how-to-*.md`）。
- 性能基准测试的完整原始数据。

### 1.3 干系人与关注点

| 干系人 | 角色 | 主要关注点 |
|--------|------|-----------|
| 密钥管理员 | 通过 Web UI/REST 管理密钥的社区成员 | 密钥生命周期可控、操作可审计、公开密钥删除需多方确认 |
| CI/CD 系统 | COPR / openEuler 构建系统等自动化签名消费方 | 签名接口稳定、高吞吐、可脚本化（Token 认证）、可按项目隔离密钥 |
| 运维团队 | 负责生产部署与稳定性的 SRE | 可观测性、可用性、水平扩展、配置外部化、依赖故障隔离 |
| 安全团队 | 负责密钥安全与合规的审计方 | 私钥不落盘 / 不下发、传输加密、国密合规、攻击面最小化 |
| 社区贡献者 | 参与开发的开源开发者 | 架构清晰、模块可替换、领域边界明确、易于扩展新签名格式 |
| 下游验证方 | 使用公钥验证签名的最终用户 | 公钥 / 证书可导出、CRL 可获取、指纹可校验 |

### 1.4 术语表

| 术语 | 含义 |
|------|------|
| **PGP / OpenPGP** | Pretty Good Privacy，用于 RPM/SRPM、ISO checksum、仓库元数据签名 |
| **X509** | X.509 证书标准，用于内核模块、EFI、IMA 签名；本系统支持三级证书层级 |
| **CA / ICA / EE** | 根证书颁发机构 / 中间 CA / 终端实体（End-entity）证书 |
| **CMS / PKCS#7** | Cryptographic Message Syntax，用于 EFI/内核模块的签名封装，支持国密 SM2/SM3 |
| **IMA** | Integrity Measurement Architecture，Linux 内核完整性度量子系统的文件签名 |
| **EFI** | 可扩展固件接口，Secure Boot 场景下的镜像签名 |
| **SKID** | Subject Key Identifier，X509 证书的主体密钥标识扩展 |
| **CRL** | Certificate Revocation List，证书吊销列表 |
| **SM2 / SM3** | 中国国家商用密码算法：SM2（椭圆曲线签名）、SM3（摘要），遵循 GM/T 系列规范 |
| **KMS** | Key Management Service，外部密钥管理服务（如华为云 KMS），提供主密钥加解密 |
| **mTLS** | 双向 TLS，客户端与服务端互相校验证书 |
| **OIDC** | OpenID Connect，基于 OAuth 2.0 的身份认证协议 |
| **zeroize** | 使用后将内存中的敏感数据显式清零，防止残留泄漏 |
| **Cluster Key** | 系统内部的二级加密密钥（AES），用于在 KMS 之上再加密数据密钥内容，支持轮换 |
| **DataKey** | 系统核心实体，代表一个可用于签名的密钥对（含私钥 / 公钥 / 证书） |

---

## 2. 概念模型

### 2.1 核心领域概念

Signatrust 的领域模型围绕**密钥生命周期管理**和**签名操作**两个核心流程构建。

```
┌──────────────────────────────────────────────────────────────┐
│                     领域概念关系图                             │
│                                                                │
│  ┌──────┐  1:N  ┌─────────┐  N:1  ┌────────────────┐          │
│  │ User │──────→│  Token  │       │    DataKey     │          │
│  │      │       └─────────┘       │                │          │
│  │      │  1:N                    │ - name         │          │
│  │      │───────────────────────→ │ - visibility   │          │
│  └──────┘        (owner)          │ - key_type     │          │
│                                   │ - key_state    │          │
│  ┌────────────┐                   │ - fingerprint  │          │
│  │ ClusterKey │──────────────────→│ - serial_number│          │
│  │ (二级密钥)  │   加密 DataKey     │ - parent_id    │          │
│  └────────────┘   私钥内容         │ - attributes   │          │
│                                   └───────┬────────┘          │
│                                           │ 1:N (CA → EE)      │
│                      ┌────────────────────┼───────────┐       │
│                      │                    │           │       │
│                ┌─────┴──────┐    ┌────────┴─────┐ ┌───┴──────┐│
│                │ Pending    │    │ X509 CRL     │ │ Revoked  ││
│                │ Operation  │    │ Content      │ │ Key      ││
│                │(删除/吊销)  │    │ (每 CA 一份) │ │(ca+key)  ││
│                └────────────┘    └──────────────┘ └──────────┘│
└──────────────────────────────────────────────────────────────┘
```

**核心实体**

- **DataKey（数据密钥）** — 系统的核心实体，代表一个可用于签名的密钥对。承载私钥（加密态）、公钥、证书（X509）、指纹、序列号、属性等。X509 类型密钥通过 `parent_id` 形成 CA → ICA → EE 的证书链关系。

- **KeyState（密钥状态机）** — 6 种状态，严格控制密钥生命周期：

  ```
  Enabled ⇄ Disabled ──→ PendingRevoke ──→ Revoked
                │              │
                │              └──←── (CancelRevoke)
                │
                └──→ PendingDelete ──→ Deleted
                          │
                          └──←── (CancelDelete)

  说明：方框内为 6 个状态节点（Enabled / Disabled / PendingRevoke /
        Revoked / PendingDelete / Deleted）；括号中的 CancelRevoke /
        CancelDelete 为转换动作，不计入状态数。
  ```

  - 公开密钥（Public）删除需**多重管理员确认**：一个管理员发起删除 → 进入 `PendingDelete` → 共需 3 名不同管理员提交请求（发起者计 1 名，另需 2 名确认，阈值 = 3）→ 完成删除。
  - 私有密钥（Private）删除：所有者可直接操作（阈值 = 1），无需多重确认。
  - 吊销（Revoke）流程与删除**对称**，采用同一确认阈值：公开密钥吊销同样需 ≥3 名管理员确认，私有密钥所有者可直接吊销；发起 / 确认 / 取消机制一致，X509 密钥吊销时可指定吊销原因。
  - 阈值设计：删除与吊销共用同一组阈值常量（公开 = 3、私有 = 1），当前为固定值。`pending_operation` 表以 `(user_id, key_id, request_type)` 唯一约束保证同一管理员对同一操作只计一次。

- **KeyType（密钥类型）** — 4 种：

  | 枚举值 | 说明 | 典型签名场景 |
  |--------|------|-------------|
  | `OpenPGP` | PGP 密钥对 | RPM/SRPM、ISO checksum、仓库元数据 |
  | `X509CA` | 根 CA 证书 | 仅用于签发下级证书，不直接签名 |
  | `X509ICA` | 中间 CA 证书 | 仅用于签发下级证书 |
  | `X509EE` | 终端实体证书 | 内核模块、EFI 镜像、IMA 文件签名 |

  > 注：**CMS 是签名封装方式（SignType），不是密钥类型**。CMS 签名在 X509EE 密钥之上通过 CMS 插件实现。

- **SignType（签名封装类型）** — 5 种：`Cms`、`KernelCms`、`Authenticode`（EFI）、`PKCS7`、`RsaHash`（IMA）。

- **Visibility（密钥可见性）** — 2 种：

  | 枚举值 | 可见范围 | 删除方式 |
  |--------|---------|---------|
  | `Public` | 所有管理员可见、可创建 / 使用 | 需多重管理员确认（≥3） |
  | `Private` | 仅所有者可见（通过 Token 中 email 前缀验证） | 所有者直接删除 |

- **User / Token（用户 / 令牌）** — 用户通过 OIDC 协议集成的外部身份认证。登录后获得 Token，编程式 API 操作携带 Token。Token 有过期时间。

- **SignPlugins（签名算法插件）** — 策略模式实现的可替换签名算法（领域 trait 名为 `SignPlugins`），工厂根据 `KeyType` 选择：`OpenPGP` / `X509` / `CMS` 三类插件。

- **KMSProvider（密钥管理服务）** — 外部 KMS 系统的抽象接口，负责 Cluster Key 的透明加密 / 解密：`HuaweiCloud`（生产）与 `Dummy`（本地开发，无实际加密）两种实现。

- **EncryptionEngine（加密引擎）** — 数据加密层抽象，在 KMS 加密之上提供第二层加密保护。采用 **AES-256-GCM-SIV** 算法（`aes-gcm-siv` crate），使用 **Cluster Key** 作为加密密钥，支持密钥轮换（默认 90 天）。此存储加密层与**签名算法**是独立关注点——国密 SM2/SM3 合规属于签名侧，由 CMS 签名插件（遵循 GM/T 0010）实现。

### 2.2 五层密钥保护模型

```
┌─────────────────────────────────────────────┐
│ Layer 5: 安全释放                            │
│ - 内存密钥通过 secstr::SecVec 管理            │
│ - Drop 时自动 zeroize 内存                    │
│ - 防止 swap / core dump 泄漏                  │
├─────────────────────────────────────────────┤
│ Layer 4: 内存保护                            │
│ - 密钥仅在使用时于服务端内存中解密             │
│ - 私钥永不下发给客户端                         │
│ - 签名计算在服务端内存中完成                   │
├─────────────────────────────────────────────┤
│ Layer 3: 传输安全                            │
│ - mTLS 客户端-服务器双向认证                  │
│ - gRPC 调用级 Token 验证                      │
│ - HTTP REST 经 OIDC + Session/Token          │
├─────────────────────────────────────────────┤
│ Layer 2: 存储加密（AES 引擎层）              │
│ - AES-256-GCM-SIV 二级加密                    │
│ - 密钥内容存入 DB 前再次加密                   │
│ - Cluster Key 90 天自动轮换                    │
├─────────────────────────────────────────────┤
│ Layer 1: 存储加密（KMS 层）                  │
│ - 外部 KMS（华为云 KMS）主密钥                │
│ - 透明加密 / 解密 Cluster Key                 │
└─────────────────────────────────────────────┘
```

**保护链路**：DataKey 私钥内容 →（Layer 2）用 Cluster Key 做 AES-256-GCM-SIV 加密 →（Layer 1）Cluster Key 本身由外部 KMS 主密钥加密 → 密文入库。使用时逆向解密至内存（Layer 4），签名后立即 zeroize（Layer 5）。全过程私钥不落盘、不出服务端（Layer 3 保证传输边界）。

---

## 3. 架构目标与质量属性

### 3.1 架构目标

| 目标 | 描述 |
|------|------|
| 安全优先 | 私钥永不离开服务器，5 层加密保护、mTLS、内存 zeroize；安全性是不可妥协的第一优先级 |
| 高吞吐 | 支持数千并发签名请求，单实例可处理 4000+ RPM 包 / 批签名 |
| 多格式支持 | 统一平台覆盖 PGP / X509 / CMS 签名场景 |
| 数据面可扩展 | 数据面可水平扩展，控制面独立伸缩 |
| 可替换性 | KMSProvider、SignPlugins、EncryptionEngine 均基于 trait 抽象，核心组件可替换 |
| 合规性 | 支持国密 SM2/SM3 算法，满足中国密码法规要求 |
| 可运维性 | 配置外部化，支持 ConfigMap/Secret 挂载，健康检查端点 |

### 3.2 关键架构需求

**功能性需求**

- 支持 PGP 密钥生成、导入、导出、删除、吊销。
- 支持内联 PGP 签名与分离 PGP 签名（ISO checksum、仓库元数据）。
- 支持 X509 三层 CA 证书管理（Root / Intermediate / End-entity）。
- 支持内核模块签名、EFI 镜像签名、IMA 文件签名、通用文件签名。
- 支持 CMS/PKCS#7 格式签名（含国密 SM2/SM3）。
- 支持证书吊销列表（CRL）生成（9 种 RFC 5280 吊销原因码）。
- 提供 Web UI 进行密钥与令牌管理，提供 Swagger API 文档与健康检查。
- 提供密钥 CRUD REST API 与用户 / Token 管理 API。
- 提供签名客户端（CLI + Worker daemon）与签名身份认证（证书 + Token）。

**非功能性需求**

| 维度 | 需求 |
|------|------|
| 签名吞吐量 | 单实例 8CPU/8GB 下 ≥ 4000 RPM 包 / 批 |
| 密钥安全 | 私钥内存解密 → 签名 → zeroize；KMS + AES 双层加密入库 |
| 通信安全 | mTLS + OIDC/Token 双重认证；生产环境强制启用 TLS |
| 数据面可扩展性 | 支持 DNS round-robin 水平扩展 |
| 存储持久性 | MySQL 持久化密钥元数据和加密后密钥内容 |
| 可用性模型 | 控制面单实例（可接受短时不可用），数据面多实例 |

### 3.3 质量属性场景

以可度量的"刺激—响应"场景表述关键质量属性：

| 质量属性 | 场景（刺激 → 环境 → 响应 → 度量） |
|---------|-----------------------------------|
| 性能 | COPR 提交一批 RPM 包 → 单 data-server 8CPU/8GB → 流式分块签名 → 吞吐 ≥ 4000 包 / 批 |
| 安全（机密性） | 攻击者获取到 DB 快照 → 生产环境 → 密钥内容为 KMS+AES 双层密文 → 无 KMS 主密钥无法还原私钥 |
| 安全（传输） | 中间人尝试截获 gRPC 流量 → 生产环境 → mTLS 双向证书校验 → 连接被拒绝 |
| 可用性 | 某个 data-server 实例宕机 → 多实例 Headless Service → Client 侧重试切换至健康实例 → 签名请求成功、无人工介入 |
| 可扩展性 | 签名负载翻倍 → K8s 环境 → 增加 data-server 副本数 → 客户端 DNS round-robin 自动感知新实例 |
| 可恢复性 | 控制面进程崩溃 → 生产环境 → K8s Recreate 重启 + Session 存于 Redis → 管理员无需重新登录关键会话数据 |
| 可维护性 | 新增一种签名格式 → 开发环境 → 实现 SignPlugins trait + 注册工厂 → 无需改动核心签名流程 |

### 3.4 假设与约束

**假设**

- 外部 KMS 服务（华为云 KMS）可用且安全。
- OIDC 身份提供商（openEuler OneID）可用。
- 客户端与服务端之间网络延迟在可控范围内。
- 签名操作是 CPU 密集型（非 IO 密集型）。
- 可接受控制面短时不可用（不影响数据面签名）。

**约束**

- Rust 语言开发，锁定 `nightly-2023-08-08` 工具链。
- 关系型数据库（MySQL 8.0）存储元数据。
- Session 管理与缓存依赖 Redis。
- 生产环境运行在 openEuler 香港 Kubernetes 集群，镜像仓库 / KMS / 块存储绑定华为云基础设施。
- 采用 Mulan PSL v2.0 许可证，华为版权。

---

## 4. 架构原则

### 4.1 战略性原则

| 原则 | 体现 |
|------|------|
| 安全优先 | 安全性是不可妥协的第一优先级；私钥永不离开服务端、5 层加密、内存 zeroize |
| 控制 / 数据面分离 | 管理操作与签名操作在独立进程中运行，各自独立伸缩与故障隔离 |
| 显式依赖 | MySQL、Redis、KMS、OIDC 均为显式外部依赖，不隐藏 |
| 可替换性 | 通过 trait 抽象，核心组件（KMS / 插件 / 加密引擎）可替换 |
| 配置外部化 | 使用 Vault/Secrets Manager 外部注入，配置通过文件 / ConfigMap / Secret 挂载 |

### 4.2 结构性原则

| 原则 | 体现 |
|------|------|
| 单一职责 | 每个二进制组件只负责一个明确的职责 |
| DDD 分层 | domain（纯 trait）→ application（用例编排）→ infra（具体实现）→ presentation（表现层），依赖方向向内 |
| 端口与适配器 | 领域层定义接口（Ports），基础设施层提供实现（Adapters） |
| 约定优于配置 | 合理的默认值，减少必需配置项；配置文件只覆盖差异项 |
| 无状态数据面 | 数据面不持有持久状态，签名在内存中完成，便于水平扩展 |

---

## 5. 上下文与用例模型

### 5.1 系统上下文模型

```
┌──────────────────────────────────────────────────────────────────┐
│                        Signatrust 系统上下文                       │
│                                                                    │
│  ┌──────────┐     ┌──────────┐     ┌──────────────┐               │
│  │ 管理员    │────→│ Web UI   │     │  CI/CD 系统   │               │
│  │ (浏览器)  │     │ (Nginx + │     │ (COPR/Jenkins │               │
│  │          │     │  Vue.js) │     │  /GitHub Act.)│               │
│  └──────────┘     └────┬─────┘     └──────┬───────┘               │
│                        │                  │                        │
│  ┌─────────────────────┼──────────────────┼──────────────────┐    │
│  │            Signatrust 核心系统          │ (gRPC + mTLS)     │    │
│  │  ┌────────────┐     ┌──────────────┐   │                  │    │
│  │  │ control-   │     │  data-server │←──┘ (CI/CD → 签名)    │    │
│  │  │ server     │     │  (gRPC       │                      │    │
│  │  │ (HTTP REST)│     │   streaming) │  ← 两者不直接调用，    │    │
│  │  └─────┬──────┘     └──────┬───────┘    经 MySQL 解耦共享   │    │
│  │        │                   │             密钥元数据         │    │
│  │  ┌─────┴───────────────────┴────────┐                     │    │
│  │  │         MySQL 8.0                │                     │    │
│  │  │  (密钥元数据 + 加密后密钥内容)    │                     │    │
│  │  └─────────────────────────────────┘                     │    │
│  │  ┌─────────────────────────────────┐                     │    │
│  │  │         Redis 7.2 (Session)     │  ← 仅 control-server  │    │
│  │  └─────────────────────────────────┘     使用             │    │
│  └──────────────────────────────────────┼──────────────────┘    │
│                                          │                        │
│  ┌──────────┐  ┌──────────────┐  ┌───────┴──────┐                │
│  │ 华为云   │  │ OIDC Provider│  │ Kafka         │                │
│  │ KMS      │  │ (OneID)      │  │ (可选, 证书    │                │
│  │ (密钥    │  │              │  │  到期检查)     │                │
│  │  加密)   │  │              │  │               │                │
│  └──────────┘  └──────────────┘  └───────────────┘                │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │              下游消费系统                                  │     │
│  │  ┌──────────┐  ┌──────────────┐  ┌────────────────────┐  │     │
│  │  │ COPR     │  │ openEuler    │  │ 其他 Linux 发行版   │  │     │
│  │  │ (Fedora) │  │ 构建系统     │  │ 构建系统            │  │     │
│  │  └──────────┘  └──────────────┘  └────────────────────┘  │     │
│  └──────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

**外部集成边界**

| 外部系统 | 交互方向 | 协议 | 用途 |
|---------|---------|------|------|
| OIDC Provider (OneID) | control-server → OIDC | HTTPS/OAuth2 | 管理员身份认证 |
| 华为云 KMS | infra → KMS | HTTPS REST | Cluster Key 加解密 |
| MySQL 8.0 | control/data → DB | MySQL 协议 | 密钥元数据与密文持久化 |
| Redis 7.2 | control → Redis | RESP | Session、缓存、限流计数 |
| Kafka（可选） | control → Kafka | Kafka 协议 | 证书到期检查通知 |
| CI/CD（COPR 等） | client/CI → data-server | gRPC + mTLS | 批量文件签名 |

### 5.2 关键用例

**UC1：管理员管理密钥（控制面）**

```
管理员 → 登录（OIDC）→ 获得 Token
      → 创建密钥（选择类型 / 算法 / 属性）
      → 查看密钥列表（分页 / 过滤）
      → 导出公钥 / 证书 / CRL
      → 吊销密钥（X509 可指定吊销原因）
      → 删除密钥（公开密钥需多重确认）
```

**UC2：客户端签名文件（数据面）**

```
客户端 → 接收签名任务
      → gRPC GetKeyInfo 获取目标密钥信息
      → gRPC SignStream 流式发送文件内容
      → 服务端内存解密私钥 → 执行签名 → 返回签名 → zeroize 私钥
      → 客户端将签名注入目标文件
```

**UC3：COPR 构建系统集成**

```
COPR → 创建项目密钥对（Private 可见性，email 前缀绑定）
     → 对构建产出的 RPM 包逐一签名
     → 删除项目时同步删除密钥对
     → 导出公钥供用户验证
```

**UC4：证书生命周期管理**

```
管理员 → 创建 Root CA → 创建 Intermediate CA → 签发 End-entity 证书
       → 定期生成 CRL（默认 30 天刷新）
       → 吊销终端证书（支持 9 种 RFC 5280 吊销原因）
```

---

## 6. 关键架构决策（ADR）

以架构决策记录（ADR）形式呈现关键技术方案，每条包含**问题背景**、**决策**、**备选方案**与**权衡**。本节所列 ADR-1 ~ ADR-8 均为**已采纳（Accepted）**的现行设计决策，无已被取代项。

### ADR-1：控制面 / 数据面分离

- **问题**：管理操作（低频、需强一致性）与签名操作（高频、需高吞吐）的资源与可靠性需求不同，单一进程难以同时满足。
- **决策**：拆分为两个独立服务——control-server（HTTP REST，管理面）与 data-server（gRPC，签名面），各自独立部署与伸缩。
- **备选方案**：① 单体进程内多线程隔离；② 按租户分片。
- **权衡**：分离带来跨进程一致性成本（密钥元数据经 DB 共享），但换取了故障隔离（控制面故障不影响签名）与独立伸缩能力；相比单体，运维组件数量增加。

### ADR-2：内存签名后端（Memory SignBackend）

- **问题**：私钥的存储与使用面临两难——磁盘存储不安全，专用 HSM 访问延迟高且成本大。
- **决策**：采用 Memory SignBackend——密钥以双层加密态存 DB，签名时解密到内存、执行、立即 zeroize，私钥永不落盘、不下发客户端；内存密钥用 `secstr::SecVec<u8>` 管理，Drop 自动清零。
- **备选方案**：① 硬件 HSM；② 密钥文件挂载。
- **权衡**：牺牲了 HSM 级别的硬件隔离，换取低延迟与部署简易；安全性依赖 KMS + AES 双层加密与内存管理纪律。

### ADR-3：gRPC 流式签名

- **问题**：大文件（RPM 包、ISO 镜像）一次性传输到服务端内存消耗大、延迟高。
- **决策**：使用 gRPC 客户端流（`stream SignStreamRequest`）——客户端分块发送、服务端流式接收并聚合、返回单一签名结果。客户端默认 `buffer_size = 20480`（20KB 块）、`max_concurrency = 100`。
- **备选方案**：① 一次性 unary 请求；② 客户端本地计算摘要后仅上传摘要。
- **权衡**：流式降低内存峰值、支持大文件，代价是协议与错误处理复杂度上升；相比"仅上传摘要"，牺牲带宽换取服务端对完整内容的控制（部分格式需服务端处理原文）。

### ADR-4：DNS Round-Robin 负载均衡

- **问题**：data-server 需水平扩展，客户端如何发现多个实例？
- **决策**：data-server 使用 Headless Service（`clusterIP: None`），客户端配置 `type = "dns"`，DNS 解析返回所有 Pod IP，客户端侧 round-robin 选择，实现客户端负载均衡。
- **备选方案**：① 服务端负载均衡器（L4/L7 LB）；② 服务网格（Istio 等）。
- **权衡**：客户端 LB 无中间跳、延迟低、无单点，但要求客户端实现健康感知与重试；相比服务网格，减少了基础设施依赖但功能较基础。

### ADR-5：OIDC 认证集成

- **问题**：管理员如何安全登录？如何与 openEuler 社区账户体系打通？
- **决策**：control-server 集成 `openidconnect` crate，对接 OIDC Provider（OneID）。授权码流程：浏览器 → control-server → 重定向 OIDC → 授权码回调 → 获得 id_token → 创建 Session（Redis）。配合 Token 有效期管理、CSRF 保护、速率限制（默认 100 req/min）。
- **备选方案**：① 自建用户名密码体系；② LDAP。
- **权衡**：复用社区身份、免维护凭据库，代价是运行期强依赖 OIDC 可用性。

### ADR-6：密钥可见性模型（Public / Private）

- **问题**：COPR 集成场景下每个项目需独立密钥对（可能数百个），需要更灵活的权限模型。
- **决策**：引入 Public（多管理员共管）/ Private（单所有者，通过 Token 中 email 前缀验证）两种可见性。
- **备选方案**：① 仅全局共享密钥；② 完整 RBAC 角色系统。
- **权衡**：以轻量的二元可见性 + email 前缀绑定满足项目级隔离，避免引入完整 RBAC 的复杂度。

### ADR-7：国密 SM2/SM3 合规

- **问题**：中国密码法规要求关键基础设施使用国密算法。
- **决策**：在 **CMS 签名插件**中支持 SM2（签名）+ SM3（摘要）组合，OID 体系遵循 GM/T 0010 规范，通过独立的 CMSPlugin 实现，不影响现有 PGP/X509 插件。
- **备选方案**：① 全系统替换为国密；② 外部国密网关。
- **权衡**：以插件化方式局部引入国密支持，兼容既有算法，代价是需维护 SM2 特有的 Z 值计算（用户 ID）与 OID 细节。

### ADR-8：三层 CA 证书体系

- **问题**：X509 签名场景需要证书链管理，满足 EFI Secure Boot 对证书层级的要求。
- **决策**：Root CA → Intermediate CA → End-entity 三级层级。CA/ICA 仅签发下级证书、不直接签名；EE 证书用于实际签名。支持 CRL 生成（9 种 RFC 5280 原因码），支持证书到期管理（可选 Kafka 集成通知）。
- **备选方案**：① 单层自签名；② 外部商业 CA。
- **权衡**：三层结构隔离根密钥风险、符合安全启动要求，代价是证书链管理与 CRL 维护的复杂度。

---

## 7. 逻辑架构

### 7.1 DDD 分层逻辑架构

Signatrust 采用六边形架构（Ports & Adapters）+ DDD 分层：

```
┌─────────────────────────────────────────────────────────────────┐
│                    Presentation Layer（表现层）                   │
│  ┌──────────────────────┐          ┌──────────────────────────┐  │
│  │   Control API        │          │    Data API              │  │
│  │  ┌─────────────────┐ │          │  ┌─────────────────────┐ │  │
│  │  │ REST Handler    │ │          │  │ gRPC Handler        │ │  │
│  │  │ - datakey       │ │          │  │ - GetKeyInfo        │ │  │
│  │  │ - user          │ │          │  │ - SignStream        │ │  │
│  │  │ - health        │ │          │  │ - HealthCheck       │ │  │
│  │  └────────┬────────┘ │          │  └──────────┬──────────┘ │  │
│  │  ┌────────┴────────┐ │          │  ┌──────────┴──────────┐ │  │
│  │  │ Middleware       │ │          │  │ Interceptor         │ │  │
│  │  │ - Auth (OIDC)   │ │          │  │ - Auth (mTLS+Token) │ │  │
│  │  │ - CSRF          │ │          │  └─────────────────────┘ │  │
│  │  │ - Rate Limit    │ │          │                          │  │
│  │  └─────────────────┘ │          │                          │  │
│  └──────────────────────┘          └──────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                  Application Layer（应用层）                      │
│  ┌──────────────────────┐    ┌──────────────────────────────┐   │
│  │ DataKey Service      │    │ User Service                 │   │
│  │ - create_key()       │    │ - authenticate()             │   │
│  │ - list_keys()        │    │ - create_token()             │   │
│  │ - revoke_key()       │    │ - validate_token()           │   │
│  │ - delete_key()       │    └──────────────────────────────┘   │
│  │ - sign()             │                                        │
│  └──────────┬───────────┘                                        │
├─────────────┼───────────────────────────────────────────────────┤
│             │       Domain Layer（领域层 — Ports）              │
│  ┌──────────┴───────────┐  ┌────────────────────┐               │
│  │ <<trait>>            │  │ <<trait>>          │               │
│  │ SignBackend          │  │ SignPlugins        │               │
│  │ + generate_keys()    │  │ + generate_keys()  │               │
│  │ + sign()             │  │ + sign()           │               │
│  │ + rotate_key()       │  │ + validate_and_    │               │
│  │ + validate_and_upd() │  │   update()         │               │
│  │ + decode_pub_keys()  │  │ + generate_crl_    │               │
│  │ + decode_priv_keys() │  │   content()        │               │
│  │ + generate_crl_ctnt()│  └────────────────────┘               │
│  └──────────────────────┘                                        │
│  ┌──────────────────────┐  ┌────────────────────┐               │
│  │ <<trait>>            │  │ <<trait>>          │               │
│  │ KMSProvider          │  │ EncryptionEngine   │               │
│  │ + encode()           │  │ + initialize()     │               │
│  │ + decode()           │  │ + encode()         │               │
│  └──────────────────────┘  │ + decode()         │               │
│  ┌──────────────────────┐  │ + rotate_key()     │               │
│  │ <<entity>>          │  └────────────────────┘               │
│  │ DataKey / User /     │                                        │
│  │ Token / ClusterKey   │                                        │
│  └──────────────────────┘                                        │
├─────────────────────────────────────────────────────────────────┤
│              Infrastructure Layer（基础设施层 — Adapters）        │
│  ┌────────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────┐    │
│  │ Memory     │ │ OpenPGP  │ │ Huawei   │ │ AES-256-GCM-SIV│    │
│  │ Backend    │ │ /X509    │ │ Cloud    │ │ Engine         │    │
│  │            │ │ /CMS     │ │ KMS/Dummy│ │                │    │
│  └────────────┘ └──────────┘ └──────────┘ └────────────────┘    │
│  ┌────────────┐ ┌──────────┐ ┌──────────────────────────────┐  │
│  │ MySQL      │ │ Redis    │ │ File System (Client Worker)  │   │
│  │ (sqlx +    │ │ (Session │ │ - walkdir scanning            │  │
│  │  sea-orm)  │ │ + Cache) │ │ - temp file management        │  │
│  └────────────┘ └──────────┘ └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**依赖方向**：presentation → application → domain ← infra。领域层不依赖任何外部实现，基础设施层通过实现领域 trait 完成依赖倒置。

### 7.2 逻辑元素清单

| 组件 | 类型 | 入口 | 职责 |
|------|------|------|------|
| **control-server** | HTTP REST 管理服务 | `control_server_entrypoint.rs` | 密钥 CRUD REST API、用户 / Token 管理、Swagger API 文档、健康检查、OIDC 登录、CRL 导出 |
| **data-server** | gRPC 签名服务 | `data_server_entrypoint.rs` | 启动 gRPC 服务器，实现 `GetKeyInfo` 与 `SignStream` RPC，内存解密 → 签名 → zeroize |
| **signatrust-client** | CLI 客户端 + Worker daemon | `client_entrypoint.rs` | 签名命令（add/list/delete），文件类型处理器（RPM/ISO/EFI/KernelModule 等 6 种），并发 Worker 线程池（默认 8），DNS/Single 负载均衡 |
| **control-admin** | 开发 / 维护工具 | `control_admin_entrypoint.rs` | CLI 管理工具入口，生成默认测试密钥、管理员账户和 Token（生产环境禁用） |
| **App (Web UI)** | Web 管理界面 | `app/`（Vue.js + pnpm） | 单页面应用，提供密钥 / 令牌管理 Web UI；独立构建，由 nginx 反向代理，API 代理到 control-server |

### 7.3 领域端口（Trait 接口）

| Trait（Port） | 关键方法 | 基础设施适配器（Adapter） |
|--------------|---------|--------------------------|
| `SignBackend` | `validate_and_update` / `generate_keys` / `rotate_key` / `sign` / `decode_public_keys` / `decode_private_keys` / `generate_crl_content` | Memory Backend |
| `SignPlugins` | `new` / `validate_and_update` / `parse_attributes` / `generate_keys` / `sign` / `generate_crl_content` | OpenPGP / X509 / CMS 插件（工厂按 KeyType 选择） |
| `KMSProvider` | `encode` / `decode` | HuaweiCloud / Dummy（工厂按配置选择） |
| `EncryptionEngine` | `initialize` / `rotate_key` / `encode` / `decode` | AES-256-GCM-SIV 引擎（Cluster Key） |
| `Repository`（各实体） | `create` / `get_by_id` / `get_latest` / `delete_by_id` 等 | sqlx / sea-orm MySQL 实现 |

### 7.4 接口契约

**gRPC 服务契约**（`proto/signatrust.proto`）：

```protobuf
service Signatrust {
  rpc GetKeyInfo(GetKeyInfoRequest) returns (GetKeyInfoResponse);
  rpc SignStream(stream SignStreamRequest) returns (SignStreamResponse);
}

message GetKeyInfoRequest  { string key_type = 1; string key_id = 2; optional string token = 3; }
message GetKeyInfoResponse { map<string,string> attributes = 1; string error = 2; }

message SignStreamRequest  { bytes data = 1; string key_type = 2; string key_id = 3;
                             map<string,string> options = 4; optional string token = 5; }
message SignStreamResponse { bytes signature = 1; string error = 2; }
```

> 错误语义：RPC 层返回 `Ok` 响应，业务错误通过响应体的 `error` 字段传递（非空即失败）；传输层错误由 gRPC status 表达，客户端据此重试。

**REST 端点契约**（control-server）：业务 API 挂载于 `/api/v1` 前缀（keys / users），健康检查单独挂载于 `/api/health/`。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/keys` | 列出密钥（分页 / 过滤） |
| POST | `/api/v1/keys` | 创建密钥 |
| POST | `/api/v1/keys/import` | 导入密钥 |
| HEAD | `/api/v1/keys/name_identical` | 校验密钥名是否重复 |
| GET | `/api/v1/keys/{id_or_name}` | 查看单个密钥 |
| GET | `/api/v1/keys/{id_or_name}/public_key` | 导出公钥 |
| GET | `/api/v1/keys/{id_or_name}/certificate` | 导出证书（X509） |
| GET | `/api/v1/keys/{id_or_name}/crl` | 导出 CRL（X509 CA） |
| POST | `/api/v1/keys/{id_or_name}/actions/enable` | 启用 |
| POST | `/api/v1/keys/{id_or_name}/actions/disable` | 禁用 |
| POST | `/api/v1/keys/{id_or_name}/actions/request_delete` / `cancel_delete` | 发起 / 取消删除 |
| POST | `/api/v1/keys/{id_or_name}/actions/request_revoke` / `cancel_revoke` | 发起 / 取消吊销 |
| GET | `/api/v1/users/info` / `login` / `callback`，POST `/logout` | OIDC 登录相关 |
| GET / POST | `/api/v1/users/api_keys` | 列出 / 新建 Token |
| DELETE | `/api/v1/users/api_keys/{id}` | 删除 Token |
| GET | `/api/health/` | 健康检查（不含版本前缀） |

**代表性请求 / 响应示例**（字段级完整规范以运行期 Swagger/OpenAPI 为准）：

```jsonc
// POST /api/v1/keys  创建密钥（请求）
{
  "name": "openeuler-release",
  "description": "openEuler 发行版签名密钥",
  "visibility": "public",           // public | private
  "key_type": "pgp",                // pgp | x509ca | x509ica | x509ee
  "attributes": {                    // 随 key_type 而异（算法、长度、DN、有效期等）
    "digest_algorithm": "sha2_256",
    "key_length": "2048",
    "expire_at": "2030-01-01T00:00:00Z"
  }
}
// 201 Created（响应，节选）
{ "id": 42, "name": "openeuler-release", "key_type": "pgp",
  "key_state": "disabled", "fingerprint": "…", "create_at": "…" }

// POST /api/v1/keys/{id_or_name}/actions/request_delete  发起删除（请求体可为空）
// 200 OK：已记录一条 pending_operation；达到阈值后密钥进入 Deleted
```

---

## 8. 运行时视图

### 8.1 签名请求端到端时序（UC2）

```
Client            data-server        KeyService        SignBackend        KMS/AES         SignPlugin
  │                    │                  │                 │                │                │
  │─GetKeyInfo────────→│                  │                 │                │                │
  │  (key_type,id,tok) │──validate token─→│                 │                │                │
  │←──attributes───────│                  │                 │                │                │
  │                    │                  │                 │                │                │
  │═SignStream═══════════════════════════════════════════════════════════════════════════   │
  │─chunk1─────────────→│                 │                 │                │                │
  │─chunk2─────────────→│ (流式聚合 data) │                 │                │                │
  │─chunkN─────────────→│                 │                 │                │                │
  │                    │──validate token─→│                 │                │                │
  │                    │──sign(type,id,───→│──load DataKey──→│                │                │
  │                    │      opts,data)   │  (加密态私钥)   │──decode────────→│               │
  │                    │                  │                 │←─明文私钥(内存)─│                │
  │                    │                  │                 │──sign(data)────────────────────→│
  │                    │                  │                 │←──signature─────────────────────│
  │                    │                  │                 │  (zeroize 私钥)                  │
  │←──SignStreamResponse(signature)───────│                 │                │                │
  │  (注入目标文件)     │                  │                 │                │                │
```

**关键点**：私钥仅在 `SignBackend.sign` 内存作用域中以明文存在，签名完成后由 `SecVec` 的 Drop 自动 zeroize；私钥全程不出 data-server 进程。

### 8.2 密钥创建时序（含双层加密，UC1）

```
Admin        control-server      KeyService      SignPlugins      EncryptionEngine       KMS         DB
  │                │                 │               │                   │                │           │
  │─POST /keys────→│──authz(Session)→│               │                   │                │           │
  │  (type,attrs)  │                 │──generate────→│                   │                │           │
  │                │                 │←─keypair──────│                   │                │           │
  │                │                 │──encode(priv)───────────────────→│                 │           │
  │                │                 │               │   (AES 加密, 用   │──encode(CK)───→│           │
  │                │                 │               │    Cluster Key)   │←─KMS 加密 CK──│           │
  │                │                 │←────────────── 双层密文 ─────────│                 │           │
  │                │                 │──persist(DataKey 密文 + 元数据)──────────────────────────────→│
  │←──201 Created──│                 │               │                   │                │           │
```

### 8.3 OIDC 登录时序（ADR-5）

```
Browser        control-server        OIDC Provider        Redis
  │                  │                     │                │
  │─GET /login──────→│──redirect──────────→│                │
  │─────────── 授权页 (用户认证) ──────────→│                │
  │←────── 授权码回调 /callback?code ───────│                │
  │─GET /callback───→│──exchange code─────→│                │
  │                  │←─id_token───────────│                │
  │                  │──create Session──────────────────────→│
  │←─Set-Cookie──────│  (CSRF token)       │                │
```

### 8.4 密钥轮换时序（Cluster Key，默认 90 天）

```
定时触发         EncryptionEngine        ClusterKeyRepo        KMS
   │                   │                      │                │
   │─rotate_key()─────→│                      │                │
   │                   │─检查 latest.create_at + 90d < now?    │
   │                   │  否 → 返回 false（不轮换）             │
   │                   │  是 ↓                                 │
   │                   │──generate new key────────────────────→│ (KMS encode)
   │                   │──create(new ClusterKey)─→│            │
   │                   │  后续新数据用新 Cluster Key 加密；      │
   │                   │  旧数据仍可用旧 key 解密（key id 前缀） │
```

> 说明：密文格式为 `[cluster_key_id(2字节)][nonce][ciphertext]`，解密时按前缀定位对应 Cluster Key，实现新旧密钥平滑共存。

### 8.5 CRL 生成时序（X509 CA，默认 30 天刷新）

```
定时触发       control-server        DataKeyRepo        SignBackend(X509)        DB
   │                │                    │                     │                  │
   │─refresh CRL───→│──列出到期 CA──────→│                     │                  │
   │                │                    │──查 revoked 列表────────────────────────│
   │                │                    │──generate_crl_content(CA, revoked)─────→│
   │                │                    │  (用 CA 私钥签名 CRL)                    │
   │                │                    │──upsert x509_crl_content────────────────→│
```

---

## 9. 数据模型

### 9.1 物理数据模型（MySQL 8.0）

```
┌─────────────┐        ┌──────────────────┐        ┌──────────────┐
│   user      │1      N│      token       │        │ cluster_key  │
│─────────────│────────│──────────────────│        │──────────────│
│ id (PK)     │        │ id (PK)          │        │ id (PK)      │
│ email (UQ)  │        │ user_id (FK)     │        │ data (密文)  │
└──────┬──────┘        │ token            │        │ algorithm    │
       │1              │ create_at        │        │ identity(UQ) │
       │               │ expire_at        │        │ create_at    │
       │N              └──────────────────┘        │ expire_at    │
┌──────┴──────────────────────────────┐            └──────────────┘
│            data_key                 │
│─────────────────────────────────────│         ┌─────────────────────┐
│ id (PK)                             │1       N│  pending_operation  │
│ name (UQ)                           │─────────│─────────────────────│
│ description                         │         │ id (PK)             │
│ visibility (public/private)         │         │ user_id (FK)        │
│ user (FK → user.id)                 │         │ key_id (FK)         │
│ attributes                          │         │ request_type        │
│ key_type / parent_id                │         │ user_email          │
│ fingerprint / serial_number         │         │ UQ(user,key,type)   │
│ private_key (密文) / public_key     │         └─────────────────────┘
│ certificate                         │
│ create_at / expire_at               │         ┌─────────────────────┐
│ key_state                           │1       N│  x509_keys_revoked  │
└──────┬──────────────────────────────┘─────────│─────────────────────│
       │1 (ca_id)                               │ id (PK)             │
       │                                        │ ca_id (FK)          │
       │1      ┌──────────────────────┐         │ key_id (FK)         │
       └───────│  x509_crl_content    │         │ reason              │
               │──────────────────────│         │ UQ(ca_id,key_id)    │
               │ id (PK)              │         └─────────────────────┘
               │ ca_id (FK, UQ)      │
               │ data (CRL 内容)     │
               │ create_at/update_at │
               └──────────────────────┘
```

### 9.2 核心表说明

| 表 | 职责 | 关键字段 |
|----|------|---------|
| `user` | 管理员账户 | `email`（唯一） |
| `token` | 编程式访问令牌 | `token`、`expire_at`（过期控制） |
| `cluster_key` | 二级加密密钥（AES） | `data`（KMS 加密态）、`algorithm`、`identity`；支持轮换 |
| `data_key` | 密钥对核心实体 | `private_key`（双层密文）、`public_key`、`certificate`、`key_type`、`key_state`、`visibility`、`parent_id`（证书链）、`serial_number` |
| `pending_operation` | 删除 / 吊销的待确认操作 | `request_type`、唯一约束 `(user,key,type)` 防重复确认 |
| `x509_crl_content` | 每个 CA 一份 CRL | `ca_id`（唯一）、`data`（签名后的 CRL） |
| `x509_keys_revoked` | 已吊销证书记录 | `ca_id` + `key_id`（唯一）、`reason`（9 种原因码）；序列号不冗余存储，生成 CRL 时按 `key_id` 关联 `data_key.serial_number` 查取 |

### 9.3 模式设计要点

数据模型体现如下关键设计决策：

| 设计决策 | 说明 |
|---------|------|
| 可见性驱动的权限模型 | `data_key.visibility`（public/private）作为权限判定的核心字段，配合 Token email 前缀实现项目级隔离 |
| 待确认操作统一建模 | 以单一 `pending_operation` 表统一承载删除与吊销两类待确认操作（`request_type` 区分），唯一约束 `(user_id,key_id,request_type)` 保证同一管理员对同一操作只计一次，是"多方确认"机制的数据基础 |
| 证书链自引用 | `data_key.parent_id` 自引用形成 Root CA → ICA → EE 的证书层级；`serial_number` 支撑 CRL 关联 |
| CRL 与吊销分离建模 | `x509_crl_content`（每 CA 一份签名后的 CRL）与 `x509_keys_revoked`（吊销明细，含 `reason`）分离，生成 CRL 时按 CA 聚合吊销明细 |
| Cluster Key 独立存储 | `cluster_key` 表独立于 `data_key`，其 `data` 为 KMS 加密态，支持轮换而不影响存量数据密钥 |

**持久化框架设计**：持久层按职责分工——需要**编译期 SQL 校验**的查询使用 `sqlx`，需要**实体关系映射**的场景使用 `sea-orm`；二者共享同一连接池，按 Repository 边界隔离，避免在同一数据访问方法内混用。

---

## 10. 实现架构与部署模型

### 10.1 实现架构

Signatrust 使用 Rust 2021 Edition 开发，锁定 `nightly-2023-08-08` 工具链。代码组织为**单一 Cargo package + 4 个二进制目标**（`[[bin]]`，非 workspace 结构），四个二进制共享同一份 `src/` 源码；Web 管理界面为独立的 Vue.js 前端工程（非 Rust 二进制）。

```
signatrust/
├── Cargo.toml              # 单 package，4 个 [[bin]] targets
├── build.rs                # 构建脚本（tonic-build 编译 proto）
├── proto/                  # Protobuf 定义
│   ├── signatrust.proto    #   Signatrust gRPC 服务
│   └── health.proto        #   gRPC 健康检查
├── src/                    # 共享源码
│   ├── domain/             #   领域层（纯 trait + 实体）
│   ├── application/        #   应用层（用例编排）
│   ├── infra/              #   基础设施层（具体实现）
│   ├── presentation/       #   表现层（HTTP handler + gRPC handler）
│   ├── client/             #   客户端逻辑（Worker/FileHandler/LoadBalancer）
│   ├── util/               #   工具（config/error/cache/sign/key）
│   └── *entrypoint.rs      #   4 个二进制入口点
├── config/                 # 默认配置文件（client.toml / server.toml）
├── deploy/                 # Kustomize 部署配置（开发）
├── docker/                 # Dockerfile（多架构：x86_64/aarch64, musl/glibc）
├── migrations/             # SQL 迁移脚本
├── app/                    # Web UI（Vue.js + pnpm，独立构建）
└── docs/                   # 技术文档
```

**构建产物**：control-server、data-server、signatrust-client、control-admin 四个二进制 + Web UI 静态资源。

### 10.2 生产部署模型（Kubernetes）

生产环境部署于 openEuler 的 Kubernetes 集群（参考 `opensourceways/infra-openeuler`）。部署拓扑表达**组件关系、服务类型与伸缩模型**的设计意图；下图不含具体副本数与资源配额（这些属可调运行参数，参考值见 §10.2.1）。

```
┌──────────────────────────────────────────────────────────────────┐
│        Kubernetes Namespace: openeuler-signatrust                  │
│        Domain: signatrust.openeuler.org                            │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                    Ingress / Gateway                         │  │
│  │         (signatrust.openeuler.org → website-service:80)      │  │
│  └────────────────────────┬────────────────────────────────────┘  │
│                           │                                        │
│  ┌────────────────────────┴─────────────────────────────────────┐ │
│  │  website (nginx)   ClusterIP: website-service                 │ │
│  │    /api/* → control-server   /oneid/* → OneID   / → Vue SPA   │ │
│  │─────────────────────────────────────────────────────────────  │ │
│  │  control-server (actix-web)   ClusterIP: control-server:8080  │ │
│  │    单实例（Recreate 策略）    InitContainer: sqlx migrate run  │ │
│  │─────────────────────────────────────────────────────────────  │ │
│  │  data-server (tonic gRPC)     Headless: data-server-headless  │ │
│  │    N 副本（可水平扩展）：8088 → 客户端侧 DNS round-robin       │ │
│  │    TLS: domain-server-crt/key + ca-root-pem                   │ │
│  │─────────────────────────────────────────────────────────────  │ │
│  │  signatrust-client (Worker Daemon)                            │ │
│  │    工作目录挂载 PVC（临时文件）                                 │ │
│  │    Server: data-server-headless:8088 (type=dns)               │ │
│  │─────────────────────────────────────────────────────────────  │ │
│  │  control-admin   仅按需运行（生产默认不常驻）                   │ │
│  └────────────────────────────────────────────────────────────────┘│
│                                                                    │
│  External: MySQL 8.0 / Redis 7.2 / Huawei KMS / OIDC(OneID)        │
│  Image Registry: SWR（华为云）                                     │
│  Secrets: Secrets Manager → Vault                                 │
└──────────────────────────────────────────────────────────────────┘
```

**伸缩与可用性设计要点**

| 组件 | 服务类型 | 伸缩模型 | 可用性策略 |
|------|---------|---------|-----------|
| website (nginx) | ClusterIP | 无状态，可多副本 | 前端静态资源，Ingress 前置 |
| control-server | ClusterIP | 单实例（管理面低频） | Recreate 重启；Session 存 Redis |
| data-server | Headless（`clusterIP: None`） | **N 副本水平扩展** | 客户端 DNS round-robin + 重试切换 |
| signatrust-client | — | Worker daemon | 挂载 PVC 缓冲任务临时文件 |
| control-admin | — | 按需 | 维护工具，非常驻 |

#### 10.2.1 参考资源配置（示例值，非设计约束）

> 下列副本数与 CPU/内存配额为某次生产部署的**参考快照**，仅用于容量估算示例；实际取值应按负载调整，不构成架构约束。

| 组件 | 副本 | CPU（req/limit） | 内存（req/limit） | 存储 |
|------|------|------------------|-------------------|------|
| website | 1 | 500m / 1000m | 500Mi / 1Gi | — |
| control-server | 1 | 1000m / 4000m | 1000Mi / 4000Mi | — |
| data-server | 1（可扩展至 N） | 4000m / 4000m | 4000Mi / 4000Mi | — |
| signatrust-client | 1 | 1000m / 2000m | 1000Mi / 2000Mi | 100Gi SSD PVC（csi-disk） |
| control-admin | 0（生产默认禁用） | — | — | — |

### 10.3 关键部署配置

**Data-server Headless Service（实现 DNS 负载均衡）**：

```yaml
apiVersion: v1
kind: Service
metadata:
  name: data-server-headless
spec:
  clusterIP: None              # Headless Service
  selector:
    component: data-server
  ports:
    - port: 8088
      targetPort: 8088
```

**Client DNS 负载均衡配置**：

```toml
[server]
domain_name  = "signatrust.openeuler.org"
type         = "dns"    # DNS round-robin
server_address = "data-server-headless.openeuler-signatrust.svc.cluster.local"
server_port  = "8088"
tls_cert     = "/signatrust/.data/certs/server/server.crt"
tls_key      = "/signatrust/.data/certs/server/server.key"
```

**Secrets 管理（Tuenti Secrets Manager → Vault）**：

```yaml
apiVersion: secrets-manager.tuenti.io/v1alpha1
kind: SecretDefinition
spec:
  name: signatrust-secrets
  keysMap:
    control-server-toml: { path: secrets/data/openeuler/signatrust, key: control-server-toml }
    DATABASE_URL:        { path: secrets/data/openeuler/signatrust, key: DATABASE_URL }
    # ... TLS certs, MySQL credentials, etc.
```

### 10.4 镜像策略

- 多架构：x86_64 / aarch64，glibc / musl 变体。
- 客户端提供 `Dockerfile.client_musl_*`（静态链接、便于分发）与 `Dockerfile.client_glibc`。
- gRPC 健康探针内置 `grpc_health_probe`。

### 10.5 开发环境部署

- **Docker Compose（本地一键）**：`docker compose up` 启动 redis + mysql + control-server + data-server。
- **Kubernetes + kind（本地集群）**：`make deploy-local`，使用 `deploy/` 目录的 kustomize 配置。

### 10.6 配置项参考（节选）

| 配置项 | 所属 | 默认值 | 含义 |
|-------|------|-------|------|
| `worker_threads` | client | 8 | 并发签名 Worker 线程数 |
| `buffer_size` | client | 20480 | gRPC 流分块大小（字节） |
| `max_concurrency` | client | 100 | 最大并发签名任务数（注意内存占用） |
| `server.type` | client | `single` / `dns` | 负载均衡模式 |
| `sign-backend.type` | server | `memory` | 签名后端类型 |
| `kms-provider.type` | server | `huaweicloud` / `dummy` | KMS 提供商 |
| `rotate_in_days` | server | 90 | Cluster Key 轮换周期（下限 90） |
| `crl_refresh_interval_days` | server | 30 | CRL 刷新周期 |
| `limits_per_minute` | server | 100 | 控制面速率限制（每分钟请求数） |
| `max_connection` | server | 5 | 数据库连接池大小 |

---

## 11. 横切关注点

### 11.1 并发模型

- 服务端基于 **tokio** 异步运行时；control-server 由 actix-web 承载 HTTP，data-server 由 tonic 承载 gRPC。
- 签名为 CPU 密集型操作，客户端 Worker 采用固定线程池（默认 8）+ 有界并发（`max_concurrency`）控制内存占用。
- 客户端签名管线为 **Splitter（分块）→ RemoteSigner（远程签名）→ Assembler（回填）** 三段式流水线，各段通过 `SignHandler` trait 串联。三段之上，客户端还包含 **FileHandler**（按文件类型分派，见 §7.2，6 种实现）负责 Splitter/Assembler 的格式细节，**LoadBalancer**（Single/DNS）负责 RemoteSigner 的连接选择，共同构成完整的客户端组件视图。

### 11.2 缓存策略

双层缓存降低数据库与 KMS 压力：

| 层 | 载体 | 内容 | 失效 |
|----|------|------|------|
| 进程内缓存 | `TimedFixedSizeCache`（固定容量 + TTL） | 热点 DataKey / User | TTL 可配置，默认 DataKey 10 分钟、User 60 分钟；容量满时**清空整表**（非逐项 LRU 淘汰） |
| 分布式缓存 | Redis | Session、限流计数 | 会话过期 / 计数窗口 |

> 缓存命中 / 未命中应作为可观测性指标暴露（见 11.4），用于评估缓存有效性。

### 11.3 错误处理策略

- 统一错误枚举 `util::error::Error`（`thiserror` 派生），覆盖数据库 / 配置 / IO / KMS / 签名 / 认证等类别，并为外部错误类型实现 `From` 转换，保证错误在分层间自然传播。
- REST 层通过 `ResponseError` 将领域错误映射到 HTTP 状态码：参数错误 → 400，未找到 → 404，未授权 → 401，越权 → 403，其余 → 500。
- gRPC 层区分**传输层错误**（gRPC status，客户端可重试）与**业务错误**（响应体 `error` 字段，不重试）。
- 设计原则：核心签名路径避免 `panic`/`expect`，对可恢复错误返回结构化 `Error`，对不可恢复的配置缺失采用安全默认值或显式启动校验。

### 11.4 可观测性设计

可观测性分三个维度设计（目标态）：

- **日志**：结构化日志，健康检查路径应从访问日志中排除以降噪。
- **指标（Prometheus 语义）**：应暴露 `/metrics` 端点，覆盖签名请求数 / 错误数 / 延迟直方图、密钥缓存命中 / 未命中、gRPC 在途请求数、数据库连接池使用率等关键指标，供容量规划与告警使用。
- **健康检查（分层）**：
  - **Liveness**：进程存活探针，返回轻量 200，用于 K8s 重启决策。
  - **Readiness**：深度就绪探针，应校验下游依赖（DB / Redis / KMS）连通性与延迟，用于流量摘挂决策。
  - gRPC 侧提供标准 gRPC Health Checking 协议实现。

### 11.5 配置与密钥外部化

- 所有环境相关配置通过文件 / ConfigMap / Secret 挂载，容器内不硬编码凭据。
- 生产密钥经 Vault / Secrets Manager 注入，配置文件只覆盖与默认值的差异项。

---

## 12. 安全 / 韧性 / 可靠性 / 可用性设计

### 12.1 安全设计

#### 12.1.1 密钥保护链路

见第 2.2 节五层模型。从存储（Layer 1/2）到传输（Layer 3）到使用（Layer 4/5）形成完整闭环，私钥全生命周期不以明文落盘、不下发客户端。

#### 12.1.2 认证与授权

```
┌────────────────────────────────────────────┐
│              认证体系                        │
│                                             │
│  控制面 (HTTP REST):                        │
│    OIDC Authorization Code Flow             │
│      ↓                                      │
│    Session Cookie (Redis backend)           │
│      ↓                                      │
│    CSRF Token (per-request)                 │
│      ↓                                      │
│    API Token (编程式访问)                    │
│                                             │
│  数据面 (gRPC):                             │
│    mTLS (客户端证书)                        │
│      +                                      │
│    Token in gRPC message body               │
│      +                                      │
│    Email-prefix verification                │
│      (私有密钥访问控制)                      │
└────────────────────────────────────────────┘
```

**访问控制矩阵**：

| 操作 | Public 密钥 | Private 密钥 |
|------|------------|-------------|
| 创建 / 使用 | 任何管理员 | 仅所有者（Token email 前缀验证） |
| 查看 | 所有管理员 | 仅所有者 |
| 删除 | 多重管理员确认（≥3） | 所有者直接删除 |

#### 12.1.3 威胁模型（信任边界与缓解）

信任边界：① 浏览器 ↔ control-server；② client/CI ↔ data-server；③ 服务 ↔ 外部依赖（KMS/OIDC/DB/Redis）。

| 威胁（STRIDE） | 场景 | 缓解设计 |
|---------------|------|---------|
| 信息泄露（DB 泄露） | 攻击者获取数据库 | KMS + AES 双层加密，密文无 KMS 主密钥不可还原 |
| 信息泄露（内存 / swap） | 内存转储 / core dump | `SecVec` + Drop zeroize，考虑 mlock 增强 |
| 篡改（中间人） | 截获 / 篡改签名流量 | mTLS 双向证书校验 |
| 假冒（越权访问私钥） | 冒用他人私有密钥 | Token email 前缀验证 + 所有权校验 |
| 权限提升（误用测试 KMS） | 生产误用 Dummy KMS | 配置校验应强制生产禁用 `dummy` 类型 |
| 抵赖（操作不可追溯） | 无法追溯敏感操作 | 密钥状态机 + pending_operation 多方确认留痕 |
| 拒绝服务 | 管理接口被刷 | 速率限制（默认 100 req/min） |

**安全强化方向（设计建议）**：编制正式威胁模型文档与 `SECURITY.md`；生产配置强制启用 TLS（移除明文选项）与禁用 Dummy KMS；对内存密钥考虑 `mlock` 防换出。

### 12.2 韧性设计

| 韧性机制 | 设计 |
|---------|------|
| 控制 / 数据面隔离 | 控制面故障不影响数据面签名（关注点分离） |
| 客户端重试与故障转移 | Headless Service + 客户端侧重试 → 自动切换至健康实例 |
| 远程调用重试 | 对传输层瞬态错误（网络不可达、5xx）采用指数退避重试，对业务错误不重试 |
| 任务队列缓冲 | 客户端 Worker 侧对签名任务排队，吸收短时抖动 |
| 密钥轮换平滑 | 密文携带 Cluster Key id 前缀，新旧密钥共存，轮换不影响存量数据解密 |

### 12.3 可靠性设计

| 维度 | 设计 |
|------|------|
| 错误传播 | Rust 类型系统 + `thiserror`/`anyhow` 提供完备错误传播，核心路径避免 panic |
| 数据一致性 | 关键状态变更（删除 / 吊销）经状态机 + 待确认表，唯一约束防重复确认 |
| 配置健壮性 | 关键配置缺失采用安全默认值或启动期显式校验，避免运行期崩溃 |
| 存储可靠性 | 密钥元数据与密文持久化于 MySQL，Cluster Key 独立存储 |

### 12.4 可用性设计

| 维度 | 设计 |
|------|------|
| 控制面 | 单实例 + Recreate 策略，可接受短时不可用（不影响签名） |
| 数据面 | 多实例（Headless Service + DNS round-robin），无状态、可水平扩展 |
| 健康检查 | Liveness / Readiness 分层探针；Readiness 应校验 DB/Redis/KMS 连通性 |
| 依赖故障隔离 | KMS 不可用影响加解密但签名内存路径可短时容忍；Redis 故障导致会话失效但可重新登录 |
| 外部 HA | MySQL/Redis/KMS 的高可用由外部方案保障（显式依赖） |

**依赖故障影响分析**：

| 依赖故障 | 影响 | 恢复方式 |
|---------|------|---------|
| MySQL 故障 | 密钥读写不可用 → 管理与签名受影响 | 依赖外部 HA |
| Redis 故障 | Session 丢失 → 用户需重新登录；限流降级 | 重连恢复 |
| KMS 不可用 | Cluster Key 加解密受阻 | 重试 + KMS 侧 HA |
| control-server 故障 | 管理功能不可用，签名不受影响 | K8s Recreate 重启 |
| data-server 实例故障 | 该实例请求失败 | 客户端重试切换健康实例 |

### 12.5 架构风险与设计权衡债

集中列出设计层面尚未消解的权衡与约束，供后续演进决策参考（区别于实现进度，此处描述的是**设计固有的残余风险**）：

| 风险 / 债 | 来源设计 | 影响 | 演进方向 |
|-----------|---------|------|---------|
| 内存签名后端相对 HSM 的残余风险 | ADR-2 | 私钥明文短暂存在于进程内存 | 对内存密钥引入 `mlock` 防换出；必要时提供 HSM 后端适配 |
| 控制面单点 | ADR-1 + 可用性设计 | 管理面短时不可用（不影响签名） | 若管理面需高可用，需引入多实例 + 分布式会话 |
| 持久层双框架并存 | §9.3 持久化框架设计 | sqlx 与 sea-orm 并存增加认知与维护成本 | 明确 Repository 边界，避免同方法内混用；长期可收敛为单一框架 |
| 存储加密引擎单一算法 | §2.1 EncryptionEngine | 目前仅 AES-256-GCM-SIV 一种实现 | 通过 `EncryptionEngine` trait 保留扩展点，如需多算法可扩充 |
| 多方确认阈值固定 | §2.1 状态机 | 确认阈值（公开 3 / 私有 1）为固定常量，不可按组织策略调整 | 如需策略化，可将阈值提升为配置项 |
| 外部依赖强耦合 | 系统上下文 | MySQL/Redis/KMS/OIDC 任一不可用均影响相应能力 | 依赖高可用由外部保障；关键路径设计降级策略 |

---

## 13. 附录

### 附录 A：参考资料

**代码仓库**

- Signatrust 主仓库：`gitcode.com/openeuler/signatrust`（镜像：Gitee / GitHub）
- openEuler 基础设施部署：`github.com/opensourceways/infra-openeuler`

**技术文档**（`docs/`）

- RPM/SRPM 签名指南、EFI 镜像签名指南、内核模块签名指南、IMA 签名指南、CMS 签名指南、通用文件签名指南
- COPR 集成设计：`integrate-signatrust-with-copr.md`
- CA 支持设计：`support-ca.md`
- 国密合规：`sm2-sm3-gmt-compliance.md`
- 公私钥说明：`private and public keys.md`

**关键依赖**

| 用途 | 组件 |
|------|------|
| HTTP 框架 | actix-web |
| gRPC 框架 | tonic |
| 数据库 | sqlx + sea-orm（MySQL 8.0） |
| 缓存 / 会话 | Redis 7.2 |
| 加密 | aes-gcm-siv、openssl、pgp |
| 认证 | openidconnect、csrf、actix-limitation |
| 密钥安全 | secstr（zeroize） |
| 许可证 | Mulan PSL v2.0 |

**相关系统对比**

| 系统 | 定位 |
|------|------|
| openSUSE 签名服务 | 发行版签名服务 |
| sigstore | 容器镜像 / 制品签名（OCI） |
| OpenBSD signify | 轻量签名工具 |
