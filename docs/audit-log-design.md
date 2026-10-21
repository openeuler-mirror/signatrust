# Signatrust 操作审计能力设计（Audit Log）

## Summary

Signatrust 当前操作留痕能力有限：`pending_operation` 仅覆盖删除/吊销的发起与确认动作，密钥创建、导入、启用/禁用、导出等动作无任何记录，登录与 Token 管理亦无留痕。本设计引入统一的 **审计日志（audit log）** 能力：对密钥操作（管理面）与认证/Token 操作进行全量审计，对数据面**私有密钥的获取动作（携带 token 的 GetKeyInfo）默认记录**，**不审计签名内容、不记录公钥请求**。审计日志只追加写入、失败不阻断业务，为安全审计与事件追溯提供不可抵赖的操作证据。

## Motivation

发行版签名服务的密钥状态直接决定软件供应链的信任边界。当发生密钥误删、越权使用、Token 泄露滥用等安全事件时，操作审计是事后取证与责任界定的唯一依据。现有留痕（`pending_operation`）仅覆盖删除/吊销确认流，其余敏感动作不可追溯，形成审计缺口。

### Goals

1. **密钥操作全量审计（管理面）**：创建/导入/启用/禁用/导出/删除/吊销及多方确认动作，记录操作者、对象、动作、前后状态、结果与时间；
2. **认证与 Token 操作审计**：登录成功/失败、登出、Token 创建/删除留痕（不记录 Token 明文）；
3. **数据面私有密钥获取审计（默认开启）**：仅记录**携带 token 的** `GetKeyInfo` 请求（私有密钥访问；公钥请求无操作者身份且信息本就公开，不记录），无配置开关；`SignStream`（签名内容）不审计；
4. **审计日志只追加、防篡改**：业务层仅提供写入接口，无修改/删除路径；
5. **审计不阻断业务**：审计写入失败不影响主流程（fail-open，取舍论证见业界调研）。

### Non-Goals

1. **签名内容级审计**：不记录被签名文件内容与签名请求（`SignStream`）。签名产物自证（公钥验签）+ 下游构建系统任务日志承担取证职责；
2. **审计查询界面/API**：本期仅 DB 留存与运维查询；查询 API 与权限分级列入 Beta 演进目标（对齐 GitLab 实践）；
3. **审计数据自动归档/清理**：留存周期策略文档化，自动清理任务后续版本；
4. **透明日志（transparency log）**：不引入 sigstore/Rekor 类公开可验证日志，如未来需要另行立项；
5. **权限模型变更**：审计能力不改变现有 Public/Private 可见性与认证授权逻辑；
6. **密钥属性变更的细粒度记录**：本期记录状态转换（before/after_state）；attributes 字段级变更明细（对齐 GitLab `details.from/to` 粒度）留待后续版本。

## Proposal

### 业界实践调研与方案取舍（Inputs from Industry Practices）

本方案参照两个成熟审计系统——HashiCorp Vault Audit Devices 与 GitLab Audit Events——的设计实践，调研结论如下。

**HashiCorp Vault Audit Devices 要点**：

| 机制 | Vault 实践 |
|------|-----------|
| 审计范围 | 记录所有 API 请求与响应（少量豁免端点如 health 不审计）；审计日志与运行日志（operational logs）分离 |
| 敏感数据保护 | 请求/响应中的字符串值默认只写 **HMAC-SHA256 键控哈希**（如 `token_accessor` 哈希化），审计设备永不接触明文秘密；整数/布尔不哈希 |
| 请求关联 | 默认记录 `Correlation-Id`/`X-Correlation-Id` 请求头，实现审计条目与调用链的关联 |
| 审计量控制 | `elide_list_responses`：列表响应的 `keys`/`key_info` 仅记录数量而非全量键名 |
| 失败语义 | **fail-closed**：审计日志无法写入任一启用设备时，Vault 拒绝处理该 API 请求（"Vault in effect becomes unavailable"）；官方建议启用至少两个审计设备互为冗余 |

**GitLab Audit Events 要点**：

| 机制 | GitLab 实践 |
|------|-----------|
| 通用字段 | `author_id`/`author_name`、`entity_type`/`entity_id`/`entity_path`、`ip_address`、`created_at`、`target_type`/`target_id`/`target_details` |
| 变更记录 | `details` 内 `change`/`from`/`to`/`add`——审计事件显式记录变更项与前后值 |
| 事件类型化 | `event_type` 字符串枚举，每种事件类型携带其专属的结构化 payload |
| 查询能力 | 审计 API 支持 `created_after`/`created_before`（ISO 8601）、`entity_type` 过滤、keyset 分页；实例级查询限 30 天窗口；管理员认证 + per-user 限流保护查询接口 |
| 权限分级 | Group/Project 审计：Owner 可见全部、Developer 仅见本人行为——审计读取按角色分级 |

**映射到本方案的设计结论**：

1. **变更前后值**（GitLab `from`/`to`）：本方案的 `before_state`/`after_state` 与之对齐；attributes 字段级变更明细列为 Non-Goal（后续版本对齐 GitLab 粒度）；
2. **敏感信息标识符化**（Vault HMAC/accessor）：本方案不记录 Token 明文、私钥与文件内容；数据面审计记录 email 前缀（等价于 Vault 的 accessor 思想——可关联、不可还原）。对 file_hash 类摘要不再引入（见下方结论 7）；
3. **请求关联**（Vault `Correlation-Id`）：schema 新增 `request_id` **预留字段**，审计侧由请求头透传/生成；当前运行日志尚未引入 request_id，**"审计条目 ↔ 请求日志"的双向追溯需运行日志同步引入 request_id 后才完整成立**（随可观测性工作落地），落地前仅具备审计条目侧的单向关联能力；
4. **来源 IP**（Vault `remote_address` / GitLab `ip_address`）：管理面审计默认记录 `source_ip`，对齐业界实践；
5. **审计量控制**（Vault `elide_list_responses`）：本方案不审计列表/查询类动作（list/show 非敏感操作），从源头控制审计量；
6. **fail-closed vs fail-open 取舍**：Vault 选择 fail-closed（安全优先，可用性让位于不可抵赖性）。**本方案明确选择 fail-open**——Signatrust 数据面为高频签名热路径，审计是旁路能力而非安全边界本身（签名安全的边界由双层加密/mTLS/状态机保障）；管理面动作虽低频，但审计 DB 故障导致密钥管理整体不可用同样不可接受。取舍的残余风险（审计短暂丢失窗口）由运行日志旁证兜底；
7. **签名请求审计的边界**：经评审确认，`SignStream` 不审计（内容级审计被否决，见 Alternatives）；数据面仅记录**携带 token 的 `GetKeyInfo`**（私有密钥访问）——私有密钥的获取/存在性才是敏感信息，公钥请求无操作者身份、信息本就公开，不记录。该记录的真实性质是**任务级访问标记（旁证）**：标准客户端每任务恰好一次 GetKeyInfo，1 条/任务 vs SignStream 的 N 条/任务，成本降 2-3 个数量级；但它**可被绕过**（持有 token 的恶意客户端可跳过 GetKeyInfo 直接调 SignStream），**不构成安全边界**，取证价值为旁证性质；
8. **查询能力**（GitLab 审计 API）：查询 API、权限分级、限流保护列为 Beta 演进目标，本期仅 DB 留存。

### User Stories (Optional)

**Story 1：安全审计员追溯密钥删除**
某公开密钥被删除后，安全审计员需要回答"谁在何时发起了删除、哪些管理员确认过"。当前 `pending_operation` 可追溯确认记录，但发起/取消动作与最终生效时刻没有统一时间线。审计日志将发起（request_delete）、每次确认（confirm_delete）、取消（cancel_delete）逐一记录，与 `pending_operation` 互相印证。

**Story 2：排查 Token 泄露滥用**
某 CI 系统报告其 Token 可能泄露。审计员查询数据面审计记录，回答"该 email 前缀在什么时间获取了哪些密钥的信息"，结合构建侧日志圈定受损范围。

**Story 3：故障回溯登录路径**
管理员报告无法登录。审计日志中登录失败记录（含失败原因）用于区分"OIDC Provider 故障"与"账户被暴力破解"两类场景，支撑限流策略调优。

### Notes/Constraints/Caveats (Optional)

1. **只追加写**：`AuditRepository` trait 仅暴露 `create` 方法，不提供 update/delete；业务层无修改审计记录的代码路径。DB 层防篡改（触发器）不在本期范围，但表结构预留了演进空间；
2. **失败隔离（fail-open）**：管理面审计与业务操作**不在同一事务**，审计写入失败仅记 error 日志，业务照常返回——避免审计能力成为新的故障源；审计丢失窗口极小且可接受（取舍论证见业界调研结论 6）；
3. **与 `pending_operation` 双写**：`pending_operation` 继续承载多方确认计数（唯一约束防重复），确认生效动作**同时**写审计日志。两者职责分离：计数 vs 审计，不做互相替代；
4. **操作者信息冗余**：审计记录冗余 `operator_email`、`target_key_name`——即使 `user`/`data_key` 记录后续变化或删除，审计记录仍可独立解读（对齐 GitLab `author_name`/`entity_path` 冗余展示名实践）；
5. **时钟依赖**：审计时间戳（`create_at`）依赖服务器时钟。生产环境须保证 NTP 同步（控制面/数据面节点偏差控制在分钟级）；系统不设计天级时钟漂移的容错。此约束作为部署前置条件写入文档；
6. **私有密钥审计归属**：数据面审计记录请求者 email 前缀（即 Private 密钥的所有者判定依据），不记录完整 Token（对齐 Vault accessor 实践）；
7. **敏感信息**：审计记录不含私钥、Token 明文、被签名文件内容；不引入内容哈希字段。

### Risks and Mitigations

| 风险 | 影响 | 缓解 |
|------|------|------|
| `audit_log` 表增长 | 存储膨胀、查询变慢 | 管理面每日个位数~百级记录，可忽略；数据面仅记录私有密钥请求（公钥任务不记录），按私有密钥任务量 × 300B/条估算，较全量记录降 1-2 个数量级；留存周期策略（建议 180 天）文档化，自动清理任务列入后续版本 |
| 审计写入拖慢热路径 | 签名吞吐下降 | 数据面经有界 mpsc 通道异步投递，独立任务写库；通道满时丢弃并计数告警，**绝不影响签名吞吐**；管理面同步写但动作低频 |
| 审计失败阻断业务 | 签名/管理操作不可用 | fail-open：审计失败仅记 error 日志，不向上抛错、不参与事务回滚 |
| 审计记录泄露敏感信息 | email/密钥名泄露 | 仅记录审计必需的元数据；不记 Token/私钥/内容；查询权限沿用 DB 权限模型 |
| 时钟错误导致时间失真 | 取证时间线不可信 | NTP 部署约束（见 Notes 第 5 条）；监控节点时钟偏移 |
| DB 不可用时审计丢失 | 审计缺口 | 管理面：审计失败日志留痕（运行日志可作旁证）；数据面：通道满丢弃告警 |

## Design Details

### 数据模型

新增迁移 `migrations/<timestamp>_add-audit-log.up.sql`：

```sql
CREATE TABLE audit_log (
    id BIGINT AUTO_INCREMENT,
    request_id VARCHAR(64) NULL,           -- 请求关联 ID（与运行日志关联）
    operator_user_id INT NULL,             -- 操作者 ID（数据面审计时为 NULL）
    operator_email VARCHAR(60) NULL,       -- 冗余，防 user 记录变化/删除
    target_key_id INT NULL,                -- 目标密钥
    target_key_name VARCHAR(255) NULL,     -- 冗余，防密钥删除后不可追溯
    target_token_id INT NULL,              -- Token 操作审计用
    action VARCHAR(40) NOT NULL,           -- 动作枚举
    before_state VARCHAR(20) NULL,         -- 状态转换前值
    after_state VARCHAR(20) NULL,          -- 状态转换后值
    result VARCHAR(10) NOT NULL,           -- success / failure
    error_code VARCHAR(40) NULL,           -- result=failure 时
    source_ip VARCHAR(45) NULL,            -- 来源 IP（管理面默认记录）
    create_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_key (target_key_id, create_at),
    KEY idx_operator (operator_user_id, create_at),
    KEY idx_action (action, create_at),
    KEY idx_time (create_at)
);
```

down 脚本**保留 `audit_log` 表（不 DROP，仅保留数据）**，理由见 Upgrade/Downgrade Strategy。

### 动作枚举

**管理面（AUD-01/02）**：

| action | 说明 | before/after_state |
|--------|------|--------------------|
| `create_key` | 创建密钥 | -/disabled |
| `import_key` | 导入密钥 | -/- |
| `enable_key` | 启用 | disabled/enabled |
| `disable_key` | 禁用 | enabled/disabled |
| `export_public_key` | 导出公钥 | -/- |
| `export_certificate` | 导出证书 | -/- |
| `export_crl` | 导出 CRL | -/- |
| `request_delete` | 发起删除 | */pending_delete |
| `confirm_delete` | 确认删除（达阈值生效） | pending_delete/deleted |
| `cancel_delete` | 取消删除 | pending_delete/* |
| `request_revoke` | 发起吊销 | */pending_revoke |
| `confirm_revoke` | 确认吊销（达阈值生效） | pending_revoke/revoked |
| `cancel_revoke` | 取消吊销 | pending_revoke/* |
| `login_success` / `login_failure` | 登录成功/失败（失败含原因） | -/- |
| `logout` | 登出 | -/- |
| `create_token` | 创建 Token（不记明文） | -/- |
| `delete_token` | 删除 Token | -/- |

**数据面（默认开启，仅私有密钥）**：

| action | 说明 |
|--------|------|
| `get_key_info` | **携带 token 的** GetKeyInfo（私有密钥访问），记录 email 前缀、key_id、result；公钥请求不记录 |

`SignStream`（签名）不审计。

### 埋点架构

**管理面**：选择 **handler 层显式埋点** 而非 actix 中间件统一埋点。理由：审计需要目标密钥 id/name、状态转换前后值等业务上下文，中间件仅能拿到 method/path/status，信息不完整；管理面动作低频（18 个埋点），显式调用成本低且可读性好。

- `datakey_handler.rs`：13 个动作入口调用 `AuditService::record(...)`；
- `user_handler.rs`：登录成功/失败、登出、Token 创建/删除；
- `confirm_delete`/`confirm_revoke` 的识别：`request_delete_key`/`request_revoke_key`（repository 层）返回值增加"是否达阈值生效"标志，handler 据此写 `confirm_*` 或 `request_*` 审计；
- 审计服务经 `app_data` 注入（与 key_service/user_service 同模式）；
- `request_id`：**预留字段**，审计侧由请求头透传/生成（对齐 Vault Correlation-Id 实践）；双向追溯的完整成立依赖运行日志同步引入 request_id（见业界调研结论 3）。

**数据面（仅私有密钥 GetKeyInfo 默认记录，无开关）**：

```
gRPC GetKeyInfo request
  → token 校验（既有逻辑）
  → 若请求携带 token（私有密钥）：
      构造轻量审计条目 → 投递 mpsc 有界通道（不阻塞）
                          ↓
               独立 tokio 任务消费 → 异步写 audit_log
                        （通道满：丢弃 + 错误日志计数）
  → 公钥请求（无 token）：不产生任何审计写入
```

审计条目字段：request_id、key_id、key_type、request_type（get_key_info）、email 前缀（私有密钥）、result、source_ip、create_at。`SignStream` 路径无任何审计写入。

### 配置项

```toml
# config/server.toml 新增（仅数据面）
[data-server.audit]
queue_size = 1024   # GetKeyInfo 审计投递通道容量
```

无 enable 开关：私有密钥 GetKeyInfo 审计随版本默认开启。

### Test Plan

**单元测试**：
- `Action` 枚举序列化/反序列化往返；
- `AuditService` 各便捷方法生成记录的字段正确性（含 before/after 状态）；
- 审计写入失败时错误被吞且仅留日志（mock repository 返回错误）；
- 数据面通道满时丢弃不阻塞（容量 1 的通道压入 2 条）。

**集成测试**：
- 迁移 up/down 可反复执行（forward/backward 兼容）；
- 调用 create/enable/disable/request_delete 后 `audit_log` 产生对应记录，字段完整；
- 多方确认达阈值后产生 `confirm_delete` 审计，未达阈值不产生；
- 携带 token 的 GetKeyInfo 调用后产生 `get_key_info` 审计；公钥（无 token）GetKeyInfo 与 SignStream 调用后均无审计记录；
- 模拟 DB 连接失败，业务操作仍成功。

**性能验证**：
- GetKeyInfo 审计开启（默认）与关闭（代码桩）的吞吐对比 < 5%；
- 签名（SignStream）路径性能与改造前基线无差异。

### Graduation Criteria

- **Alpha（本期）**：管理面审计（AUD-01/02）与数据面私有密钥 GetKeyInfo 审计默认开启；文档与迁移随版本发布；
- **Beta**：审计查询 API（对齐 GitLab：created_after/before 过滤、分页、按角色限权）+ 留存周期策略落地；
- **GA**：自动归档清理 + 审计告警（丢弃计数指标化）落地后宣布稳定。

### Upgrade / Downgrade Strategy

- **升级**：迁移由 control-server 的 InitContainer（`sqlx migrate run`）执行。**升级顺序约束：先升级 control-server（完成建表迁移），再升级 data-server**——data-server 新版本启动即开始写审计，若迁移尚未执行会持续写失败（fail-open 不阻断业务，但产生告警刷屏）；该顺序写入部署文档；
- **降级**：down 脚本**保留 `audit_log` 表（不 DROP，仅保留数据）**。原因：若 data-server 仍运行新版本，删除表会导致其审计后台任务持续报"表不存在"、通道积满丢弃、日志刷屏；且 DROP 会将数据面审计数据一并删除。旧版本代码不感知审计表，保留表后旧版本正常运行；
- **表缺失防御**：data-server 启动时探测 `audit_log` 表存在性（一次轻量查询），表缺失时降级为"审计关闭 + 启动日志告警一次"，而非后台任务持续失败；
- **配置兼容**：旧配置文件无 `data-server.audit` 段时取默认值（queue_size=1024），不报错。

### Version Skew Strategy

- control-server 与 data-server 镜像版本可能不一致：**`audit_log` 是两者共享的同一张 MySQL 表**，"闭环"仅指审计代码路径（管理面审计写入在 control-server，数据面审计写入在 data-server），表本身是共享基础设施——版本偏斜的表存在性风险由升级顺序约束（先 control 后 data）与 data-server 启动探测共同管理（见 Upgrade / Downgrade）；
- 跨版本兼容：新版本产生的审计记录仅由新版本读取，不存在新旧版本间的审计协议交互。

## Production Readiness Review Questionnaire

### Feature Enablement and Rollback

**How can this feature be enabled / disabled in a live cluster?**

审计能力随版本发布**默认开启**（管理面 + 数据面私有密钥 GetKeyInfo），无运行时开关。如需在已发布版本上关闭审计，须回滚至上一版本镜像（down 迁移保留审计表，旧版本不写审计）；如需精细控制，开关可作为后续版本补充（见 Alternatives）。

**Does enabling the feature change any default behavior?**

管理面：新增审计写入，业务行为不变。数据面：私有密钥 GetKeyInfo 响应路径新增一次异步通道投递（微秒级），响应内容与语义不变；公钥请求与 SignStream 路径零变化。

**Can the feature be disabled once it has been enabled (i.e. can we roll back the enablement)?**

经版本回滚（上一版本镜像）实现，历史审计记录保留（down 迁移不删除表）；回滚期间旧版本不写审计，为文档声明的可接受代价。

**What happens if we reenable the feature if it was previously rolled back?**

重新升级版本后审计写入恢复（表已存在，迁移幂等），自升级时刻起继续留痕（回滚期间的审计缺口由运行日志旁证）。

**Are there any tests for feature enablement/disablement?**

有：GetKeyInfo 审计开启与关闭（代码桩）的吞吐对比测试；迁移 up → 冒烟 → down → 旧版本冒烟路径测试。

### Rollout, Upgrade and Rollback Planning

**How can a rollout or rollback fail? Can it impact already running workloads?**

- 迁移执行失败（如字段类型冲突）：`sqlx migrate` 在 InitContainer 阶段失败会导致新版本 control-server 无法启动，**旧版本不受影响**（迁移未执行，DB 无变化）——回滚方式为使用旧镜像重建；
- 数据面通道配置过小：审计丢弃率升高（仅告警），不影响签名；
- 回滚（降级镜像）时 down 迁移**保留审计表**，审计能力消失（旧版本不写审计）但业务正常；若 data-server 仍运行新版本，其启动探测发现表存在则继续写审计（数据面审计随 data-server 版本存在），管理面审计停止。

**What specific metrics should inform a rollback?**

数据面签名吞吐下降、审计投递丢弃计数持续增长、审计写入错误日志频发。

**Were upgrade and rollback tested?**

升级/降级路径纳入集成测试矩阵（迁移 up → 冒烟 → 迁移 down → 旧版本冒烟）。

**Is the rollout accompanied by any deprecations and/or removals?**

无。`pending_operation` 与 `x509_keys_revoked` 均保留。

### Monitoring Requirements

**How can an operator determine if the feature is in use by workloads?**

`audit_log` 表行数增长；data-server 启动日志输出审计配置状态。

**How can someone using this feature know that it is working for their instance?**

执行任意密钥操作后查询 `audit_log` 出现对应记录；数据面对私有密钥（携带 token）调用 GetKeyInfo 后观察 `get_key_info` 记录产生。

**What are the reasonable SLOs for the enhancement?**

- 管理面审计写入成功率 ≈ 业务请求成功率（失败仅日志告警）；
- 数据面审计丢弃率在正常负载下 < 1%（通道容量充足时）。

**What are the SLIs an operator can use to determine the health of the service?**

- 审计写入失败计数（error 日志）；
- 数据面审计通道丢弃计数；
- `audit_log` 表增长速率（相对预期）。

**Are there any missing metrics that would be useful to have to improve observability of this feature?**

审计写入失败计数与丢弃计数的 Prometheus 指标（本期以日志形式提供，指标化随可观测性整体落地）。

### Dependencies

仅依赖既有 MySQL 8.0（无新外部服务）。数据面审计通道为进程内 tokio 机制，无消息队列依赖。

### Scalability

**Will enabling / using this feature result in any new API calls?**

无新 API。管理面复用既有 REST 请求路径；数据面审计记录在既有 GetKeyInfo 请求处理中产生。

**Will enabling / using this feature result in introducing new API types?**

无。

**Will enabling / using this feature result in any new calls to the cloud provider?**

无。

**Will enabling / using this feature result in increasing size or count of the existing API objects?**

不适用（非 K8s API 对象）。DB 层面：管理面每日个位数~百级记录；数据面仅私有密钥 GetKeyInfo 请求产生记录，按私有密钥任务量线性增长（见 Risks 估算）。

**Will enabling / using this feature result in increasing time taken by any operations covered by existing SLIs/SLOs?**

管理面：单次审计 INSERT（微秒级），相对密钥操作可忽略。数据面：私有密钥 GetKeyInfo 响应路径新增一次通道投递（内存 push，微秒级），公钥请求与签名（SignStream）路径零变化。

**Will enabling / using this feature result in non-negligible increase of resource usage?**

管理面：可忽略。数据面：通道内存占用 ≈ queue_size × 单条审计条目大小（约 1024 × 400B ≈ 0.4MB），DB 写入为单连接后台任务。

**Can enabling / using this feature result in resource exhaustion of some node resources?**

通道容量固定有界；DB 写入失败仅重试有限次并告警，不会无限堆积内存。

### Troubleshooting

**How does this feature react if the API server and/or etcd is unavailable?**

（适配：DB 不可用）管理面：审计写入失败仅记 error 日志，业务继续；数据面：后台写入任务持续失败并告警，通道积压至满后丢弃，签名与 GetKeyInfo 均不受影响。

**What are other known failure modes?**

- 时钟漂移导致审计时间失真（缓解：NTP 部署约束）；
- `operator_email`/`target_key_name` 冗余字段与源表短暂不一致（最终一致，可接受）；
- 确认动作识别依赖 repository 返回值标志，若遗漏将退化为 request 与 confirm 同语义记录（测试覆盖）；
- 版本偏斜导致表缺失（先升 data 后升 control）：data-server 启动探测兜底，表缺失时审计关闭并告警一次，不持续刷屏（见 Upgrade / Downgrade）。

**What steps should be taken if SLOs are not being met to determine the problem?**

检查 error 日志中审计失败计数与 DB 连接状态 → 检查数据面通道丢弃计数 → 检查 DB 表增长与磁盘 → 核对节点时钟偏移（NTP 状态）。

## Implementation History

- 2026-10-21：初稿（Provisional）
- 2026-10-21：评审修订——补充业界实践调研（HashiCorp Vault Audit Devices / GitLab Audit Events）与方案取舍结论（fail-open、request_id、source_ip、哈希化/accessor、from/to 对齐）;数据面审计改为 **GetKeyInfo 默认记录（无开关）**,SignStream 不审计,移除 file_hash 字段与 enable 开关
- 2026-10-22：评审修订——修正 Version Skew"闭环"表述（`audit_log` 为两服务共享表;升级顺序约束为先 control 后 data;down 脚本保留表不 DROP;data-server 启动探测表存在性）;数据面审计收窄为**仅记录携带 token 的私有密钥 GetKeyInfo**（公钥请求不记录,存储估算相应下调）;GetKeyInfo 记录定性为"任务级访问标记（旁证）,可绕过,不构成安全边界";request_id 降级为预留字段+演进目标（双向追溯需运行日志同步引入）

## Drawbacks

1. **双写维护成本**：确认动作在 `pending_operation` 与 `audit_log` 双写，两处语义需长期保持一致；
2. **审计记录可信度依赖 DB 权限**：本期不做 DB 层防篡改（触发器），拥有 DB 写权限者可修改审计记录——超出业务层的威胁模型；
3. **fail-open 的审计缺口**：审计 DB 故障期间的审计缺失只能由运行日志旁证，弱于 Vault 的 fail-closed 语义（取舍论证见业界调研结论 6）；
4. **存储与运维成本**：数据面默认审计新增存储增长，需配套留存策略（后续版本）；
5. **信息冗余的同步成本**：`operator_email`/`target_key_name` 冗余字段存在与源表不一致的窗口；
6. **无运行时开关**：已发布版本无法在不回滚的前提下关闭审计，灵活性低于可配置方案（若社区反馈需要，开关可在后续版本补充）。

## Alternatives

1. **actix 中间件统一埋点**：实现集中、代码量小，但只能拿到 method/path/status，缺少目标密钥与状态转换信息，审计价值大打折扣——**放弃**；
2. **复用 `pending_operation` 作为唯一审计源**：避免双写，但删除/吊销之外的 11 类动作无处安放，且确认计数与审计职责混合——**放弃**；
3. **数据面同步写审计**：实现简单，但给请求路径引入 DB 写入——**放弃**；
4. **引入独立审计服务（如 Kafka → 审计消费者）**：解耦最彻底、审计可靠性最高（向 Vault 多设备冗余靠拢），但引入消息队列基础设施，与项目"显式依赖最小化"原则冲突，超出本期收益——**放弃，作为长期演进方向保留**；
5. **fail-closed 语义（对齐 Vault）**：审计失败即拒绝请求，保证"无审计不操作"的强不可抵赖性——**放弃**：数据面高频签名路径不可接受审计故障即不可用；管理面可用性同样优先（取舍论证见业界调研结论 6）;
6. **审计开关可配置**：提供 enable 开关供部署方选择——**放弃**（本期）:评审结论为私有密钥获取属敏感动作应默认留痕,开关增加配置面与"忘记开启"风险;若需要可在后续版本补充;
7. **记录签名内容哈希**：取证能力更强——**放弃**:SignStream 不审计的结论下无内容可哈希;避免引入哈希计算开销与内容敏感度上升。

## Infrastructure Needed (Optional)

无新增基础设施。仅 MySQL 存储增长（见 Risks 与 Scalability 估算）。
