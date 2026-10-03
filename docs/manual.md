# nsc-filehouse 技术手册

面向开发与运维：架构与请求时序、鉴权与权限模型、数据模型与事务不变量、blob 存储与垃圾回收、完整 API 参考、
完整配置表、运维手册、测试与已知限制。部署步骤（Nekostick compose、反向代理、升级流程）见
[deployment.md](deployment.md)。

目录：[1 架构](#1-架构总览) · [2 鉴权授权](#2-鉴权与授权) · [3 数据模型](#3-数据模型) ·
[4 存储与去重](#4-存储布局与内容去重) · [5 垃圾回收](#5-垃圾回收) · [6 API](#6-api-参考) ·
[7 配置](#7-配置) · [8 运维](#8-运维手册) · [9 测试](#9-测试) · [10 已知限制](#10-已知限制与边界)

## 1. 架构总览

### 1.1 组件职责

| 位置 | 职责 |
| --- | --- |
| `cmd/filehouse/` | 子命令 `run`（默认）/ `status` / `doctor` / `register-permissions`、flag 绑定、日志、信号与 10s 优雅停机 |
| `internal/config/` | 环境变量与 flag 装载（flag > `FILEHOUSE_*` > `HOST`/`PORT` > 默认值）、校验、`Redacted()` |
| `internal/httpx/` | RFC 9457 problem 文档、请求 id、不透明游标、JSON 体限制（1 MiB）、客户端 IP 解析 |
| `internal/store/` | pgx 连接池、内嵌 goose 迁移、全部 SQL 与事务（桶、对象、blob、upload、配额、幂等） |
| `internal/blob/` | 本地内容寻址存储：`blobs/` 落盘、`tmp/` 原子写、`uploads/` 分片暂存 |
| `internal/iamauth/` | teamusers SDK 接线：JWT 验证器、权限缓存与级联、权限目录、服务凭据、失效事件订阅 |
| `internal/presign/` | HMAC-SHA256 预签名 token 的签发与校验、本地密钥文件管理 |
| `internal/gc/` | reaper：零引用 blob、孤儿文件、过期分片、过期幂等记录 |
| `internal/httpapi/` | chi 路由、中间件、运行时 / 管理面 / 预签名 handler |
| `internal/iamfixture/` | 仅测试用：模拟 teamusers（Ed25519 JWKS/JWT、权限缓存、client-credentials、权限注册） |
| `migrations/` | `0001_init.sql` 与内嵌迁移执行器 |
| `test/` | 由 `FILEHOUSE_TEST_PG` 门控的 HTTP 级集成测试 |

### 1.2 一次请求的完整时序

1. **中间件**（`Server.Handler`，按序）：`Recover` → `RequestID` → `AccessLog` → `ClientIP`。`X-Request-ID`
   合法（1–128 个可打印 ASCII）时沿用，否则生成新 id，并回写到响应头。
2. **认证**：`Authorization: Bearer <JWT>` 由 teamusers SDK 的 Verifier 用 JWKS 验签，claims 放入请求
   context。失败、缺失或格式错误统一 `401 invalid_token`。
3. **资源解析**：路径中的 bucket 名先做语法校验（非法 `400 invalid_bucket_name`），再按 `name` 查
   `buckets`（不存在 `404 bucket_not_found`）。分片上传还会加载 upload 并校验它属于该桶、未过期。
4. **权限级联**：构造 `iam.Resource{OwnerID, TeamID, Attrs}`，`Attrs` 视操作携带
   `bucket`/`key`/`size`/`content_type`/`uploader`/`part_no`，再按 `any → team → own` 顺序询问
   `filehouse:<verb>:<scope>`；首个 allow 生效，显式 deny 终止，级联耗尽即拒绝。SDK 会把权限缓存/传输
   失败折合成拒绝（reason 含 `authorization service unavailable`），因此这类失败仍返回
   `403 insufficient_permissions`；只有 authorizer 缺失、`Decide` 返回错误、列表接口 `Grants` 失败或预签名
   兑换无法拉取权限时才返回 `503 iam_unavailable`。
5. **存储事务**：写入走 `store` 的单个事务（锁桶行、校验配额、同步桶计数器与 blob refcount、写对象行）；
   读取直接查询。
6. **响应**：成功为 JSON（含 `X-Request-ID`）；失败为 `application/problem+json`，`detail` 是稳定错误码，
   `instance` 是 request id；403 额外带 `reason`（列出尝试过的权限键，不含凭据）。

### 1.3 拓扑前提

受支持的生产拓扑是**一个可写 blob 目录对应一个副本**（见 §5.6、§10）。服务自身只监听明文 HTTP，TLS 由
反向代理终止；反向代理后必须设置 `FILEHOUSE_PUBLIC_BASE_URL`，否则预签名链接的域名来自请求 Host。

## 2. 鉴权与授权

### 2.1 JWT 校验

token 只证明身份，不携带权限；权限永远由 teamusers 的权限数据决定。

| 校验项 | 行为 | 来源 |
| --- | --- | --- |
| `alg` | 使用 teamusers JWKS 中对应 `kid` 的公钥验签（teamusers 使用 Ed25519 密钥），拒绝无法验证的 token | SDK Verifier + `internal/iamauth/authorizer.go` |
| `iss` | 必须等于 `FILEHOUSE_TEAMUSERS_ISSUER`；为空时用 SDK 默认值（默认 issuer 为 `teamusers`，启动日志给 warning） | `Options.Issuer` |
| `aud` | 必须等于 `FILEHOUSE_TEAMUSERS_AUDIENCE`；为空时用 teamusers SDK 默认值 | `Options.Audience` |
| `exp` | 已过期即验证失败，返回 `401 invalid_token` | SDK Verifier |
| `sub` | 作为授权主体（`claims.Subject`）；为空时所有决策直接拒绝 | `Authorizer.Decide` |
| `kind` | Verifier 只接受 `user` 与 `service`；记录用量/配额时缺省按 `user` 处理 | `internal/iamauth`、`subjectKind` |
| `perm_ver` | 权限版本：`Grants` 只复用与 token 版本一致的缓存条目；预签名兑换在缓存未命中/过期（默认 2 分钟 TTL）或收到 NATS 失效事件后按签名内版本比对，不一致（权限已变更）即拒绝；缓存条目仍在有效期内时最长约 2 分钟内可能继续放行 | `DecideSubject`、`Grants` |

认证失败不泄漏原因，日志只记录脱敏后的错误（原始 token 被替换为 `[redacted]`）。

### 2.2 权限目录

权限键格式 `filehouse:<action>:<scope>`，`!` 前缀表示 deny，`*` 匹配恰好一个段。`register-permissions`
把下表幂等 upsert 到 teamusers（`POST {baseURL}/permissions/`，需要管理员令牌；注册方标识 `filehouse`）。
键与 `internal/iamauth/catalog.go` 逐条对应：

| 权限键 | 含义 |
| --- | --- |
| `filehouse:read:own` | 读取主体自己拥有的对象、列举自己拥有的桶 |
| `filehouse:read:team` | 读取主体所属团队拥有的桶与对象 |
| `filehouse:read:any` | 读取平台上任意桶与对象 |
| `filehouse:write:own` | 在主体自己拥有的桶中上传、覆盖、建桶、管理分片上传 |
| `filehouse:write:team` | 在主体所属团队的桶中上传与管理分片上传 |
| `filehouse:write:any` | 在任意桶中上传与管理分片上传 |
| `filehouse:delete:own` | 删除主体自己拥有的对象与空桶 |
| `filehouse:delete:team` | 删除主体所属团队的对象与空桶 |
| `filehouse:delete:any` | 删除平台上任意对象与空桶 |
| `filehouse:share:own` | 为自己拥有的桶中的对象签发预签名链接 |
| `filehouse:share:team` | 为主体所属团队的桶中的对象签发预签名链接 |
| `filehouse:share:any` | 为平台上任意对象签发预签名链接 |
| `filehouse:manage:any` | 管理面：配额、平台统计、垃圾回收 |

### 2.3 Scope 级联与显式 deny

`cascadeKeys` 依次生成：① `filehouse:<verb>:any`（总是尝试）；② `...:team`（仅当资源有 `TeamID`）；
③ `...:own`（仅当 `OwnerID == subject`）。首个 allow 通过；遇显式 deny（SDK reason `permission denied`）
立即终止并拒绝；级联耗尽同样拒绝。

桶列表接口先按持有 grants 生成候选集（`own`/`team`/`any` 粗过滤，`*` 可匹配单段），再对每个候选行重新
执行完整 `Decide` 复核，被拒的行从页中剔除，保证 fail-closed。

### 2.4 管理面空资源语义

管理面路由（`/api/v1/admin/*`）用**空资源**调用决策：没有 owner/team/attrs，级联只会尝试 `:any` 键——即
只有 `manage:any`（或带 `*` 的等价授权）能通过。

### 2.5 服务令牌

服务调用 teamusers 的权限接口需要服务身份：

- **client-credentials（推荐）**：配置 `FILEHOUSE_TEAMUSERS_CLIENT_ID` + `..._CLIENT_SECRET`，通过
  `POST /auth/client-credentials` 换取短期服务令牌；缓存到声称有效期的 80%，并发调用共享一次刷新，冷启动
  只发一次请求。失败以 `ErrServiceAuth` 上报，错误链不含 client secret 或 token。
- **静态服务令牌**：`FILEHOUSE_TEAMUSERS_SERVICE_TOKEN`。两者同时存在时静态令牌优先，`status` 与启动
  日志给出 warning；静态令牌不会轮换，仅建议临时使用。
- 两者都缺省：权限缓存填充、授权回退与权限注册都会失败（fail-closed），启动报 warning。

### 2.6 NATS 失效事件（可选）

用 `-tags nats` 构建并配置 `FILEHOUSE_TEAMUSERS_NATS_URL` 后，服务订阅 teamusers 的权限失效与 JWKS 密钥轮换事件，主动清理权限/密钥缓存。未带 tag 构建时订阅降级为 warning，缓存按自身 TTL 过期，功能不受影响，只是失效延迟更长。

## 3. 数据模型

### 3.1 表结构（`migrations/0001_init.sql`，共 7 张表）

**buckets**：`id` text PK（ULID）、`name` text UNIQUE NOT NULL、`owner_id`/`owner_kind` text NOT NULL、
`team_id` text NOT NULL DEFAULT `''`、`description` text NOT NULL DEFAULT `''`、`quota_bytes`/`quota_objects`
bigint NOT NULL DEFAULT 0（0 = 无限）、`used_bytes`/`used_objects` bigint NOT NULL DEFAULT 0（逻辑用量计数器）、
`created_at`/`updated_at` timestamptz；索引 `owner_id`、`team_id`。

**blobs**：`hash` text PK（小写 hex SHA-256）、`size` bigint NOT NULL、`refcount` bigint NOT NULL DEFAULT 0
（引用它的对象数）、`created_at`/`last_seen_at`（每次引用/释放刷新，GC grace 以它为准）；部分索引
`blobs_refcount_idx(refcount) WHERE refcount = 0`。

**objects**：复合 PK `(bucket_id, key)`；`blob_hash` text NOT NULL REFERENCES blobs(hash)（不级联删除）、
`size`、`etag`（`"<sha256>"` 带引号小写）、`content_type` DEFAULT `application/octet-stream`、`owner_id`
（最后写入者）、`metadata` jsonb DEFAULT `{}`、`created_at`/`updated_at`；`bucket_id` 外键
REFERENCES buckets ON DELETE CASCADE；索引 `objects_blob_hash_idx(blob_hash)`。

**uploads**：`id` PK、`bucket_id` FK→buckets ON DELETE CASCADE、`key`、`owner_id`、`content_type`、
`metadata` jsonb、`declared_size` bigint DEFAULT -1（-1 = 未声明）、`part_count` int DEFAULT 0、
`created_at`、`expires_at`；索引 `uploads_expires_at_idx(expires_at)`。

**upload_parts**：复合 PK `(upload_id, part_no)`，`upload_id` FK→uploads ON DELETE CASCADE、`size`、`sha256`、
`created_at`。

**quotas**：复合 PK `(subject_kind, subject_id)`（kind 由管理面限制为 `user`/`team`）、`max_bytes`/`max_objects`
bigint DEFAULT 0（0 = 无限）、`updated_at`。

**idempotency**：复合 PK `(scope, key)`、`fingerprint`（method+URI+body 的 SHA-256）、`status`（HTTP 状态码，
`0` = 进行中，`-1` = dead）、`response` bytea（`content-type\nbody` 包络）、`created_at`。

### 3.2 事务不变量

- **计数器与 refcount 同事务**：`PutObject`/`DeleteObject` 在同一事务里变动 objects 行、
  `buckets.used_bytes/used_objects` 与 `blobs.refcount`，桶行用 `SELECT ... FOR UPDATE` 加锁；计数器只允许
  由 `store` 层维护。
- **覆盖写按增量记账**：同 key 覆盖时 `deltaBytes = 新 size - 旧 size`、`deltaObjects = 0`；新 hash 的
  refcount +1，旧 hash 的 refcount -1（`GREATEST(...,0)`）；内容未变时只刷新 `last_seen_at` 与对象行。
- **配额在提交前校验**：桶配额在锁定的桶行上投影 `used + delta` 与 `quota_bytes`/`quota_objects` 比较，超出
  即 `ErrQuotaExceeded`（HTTP `413 quota_exceeded`），事务回滚、计数器保持原值；主体配额（user/team）先按主体
  取 PostgreSQL advisory lock（`filehouse:quota:user:<id>` / `:team:<id>`），再对该主体所有桶的 `used_*`
  求和后投影，并发写者不会集体超限；`0` 表示该维度不设限。
- **删除对象**：锁桶、锁对象行，删行、refcount -1、计数器减到不小于 0；物理文件不动。
- **删除桶必须为空**：锁桶后统计 objects，非空返回 `ErrBucketNotEmpty`（`409 bucket_not_empty`），不做隐式
  递归删除。
- **建桶**：`name` 唯一冲突 → `409 bucket_exists`；`owner_kind` 必填；id 为空时由 store 生成。
- **迁移**：启动时在 PostgreSQL advisory lock（键 `0x6e736366696c6577`，ASCII `nscfilew`）下执行内嵌 goose
  迁移，幂等，多实例同时启动不会互相打断。

## 4. 存储布局与内容去重

### 4.1 目录布局

```text
<FILEHOUSE_BLOB_DIR>/
├── blobs/<aa>/<bb>/<sha256>      # 内容寻址，aa/bb 为 hash 前 2/2 个 hex 字符
├── tmp/incoming-*                # 直传临时文件，fsync 后 rename 落盘
├── tmp/assemble-*                # 分片拼装临时文件
└── uploads/<uploadID>/<partNo>   # 分片暂存，partNo 从 1 开始
```

目录权限 0755；分片暂存文件（`uploads/<id>/<partNo>`）0644；`tmp/` 临时文件与最终落盘的 blob 文件由 `os.CreateTemp` 创建、rename 后保持 0600。`blobs/`、`tmp/`、`uploads/` 在启动时自动创建并做可写探测。hash 必须是 64 位小写 hex，否则视为不存在。

### 4.2 写入与去重

1. 请求体流式写入 `tmp/` 临时文件并同时计算 SHA-256；客户端提供 `X-Filehouse-SHA256` 时比对，不匹配返回
   `422 checksum_mismatch`（临时文件删除）。
2. `fsync` 后 rename 到 `blobs/aa/bb/<hash>`；目标已存在则删除临时文件（去重命中）。
3. 提交对象元数据：新 hash 的 `blobs` 行 refcount +1（不存在则插入），写 objects 行并同步桶计数器。引用相同
   内容的多个对象共享同一个 blob 文件，逻辑用量仍按对象逐个统计。

分片上传同理：`PutPart` 把分片写入 `uploads/<id>/<partNo>` 并记录 size/sha256；complete 时按提交顺序拼装到
`tmp/`，再走与直传相同的 commit 路径。

### 4.3 删除与物理回收

删除对象只做行级操作（refcount -1、计数器扣减），**不删文件**——文件可能刚被并发上传去重引用。物理文件由 GC
在 `refcount = 0` 且超过 grace 窗口后回收（§5）。因此逻辑用量（配额、`/api/v1/usage`）立即下降，而磁盘占用
滞后下降，且因去重通常小于逻辑用量之和。

## 5. 垃圾回收

reaper 启动后立即执行一轮，之后每 `FILEHOUSE_GC_INTERVAL` 一轮；`POST /api/v1/admin/gc` 可手动触发。
单轮按固定顺序执行四步，某步失败会记录 `errors` 计数并继续其余步骤。

### 5.1 零引用 blob

扫描 `refcount = 0 AND last_seen_at < now - FILEHOUSE_GC_GRACE`，每批 500、单轮最多 20000 个。处理顺序是
**先删文件、再删带 `refcount = 0` 守卫的行**：崩溃只会留下零引用行，下一轮对账，不会产生孤儿文件；守卫删除在
并发上传恰好复活该 blob 时不会命中。仅当行删除成功才计入 `blobs_deleted`/`bytes_deleted`。

### 5.2 孤儿文件与 grace 保护

孤儿文件 = 已写入 `blobs/` 但任何 `blobs` 行都不存在的内容（如被配额拒绝的提交、写盘后进程崩溃）。扫描条件是
文件 `mtime < now - grace` 且无对应行，随后删除文件。grace 同时保护在途上传：刚写入的文件 `mtime` 新于 cutoff
不会被扫走；仍在被引用的 blob 其 `last_seen_at` 不断刷新，不会进入零引用集合。

### 5.3 孤儿扫描的游标推进

孤儿扫描每轮最多检查 5000 个文件（`OrphanScanLimit` 默认值，当前未通过环境变量或 flag 暴露）。它按 hash 顺序
推进并记录"本轮最后看到的 hash"，下一轮从该 hash 之后继续；扫描到底（本轮不足一页）后游标回绕到起点。超大目录
会被拆到连续多轮对账，而不是每轮从头重扫。

### 5.4 过期分片上传

`expires_at < now` 的 upload 每批 500、单轮最多 20000 个：先删 `uploads/<id>/` 暂存目录，再删 `uploads` 行
（`upload_parts` 随外键级联删除），计入 `uploads_deleted`。

### 5.5 幂等记录清理

删除 `created_at < now - 24h` 的 `idempotency` 行，计入 `idempotency_deleted`。这里的 24h 是 reaper 内固定
保留期，与 `FILEHOUSE_IDEMPOTENCY_TTL`（HTTP 重放窗口）是两个独立参数。

### 5.6 并发删除竞态与恢复

"带守卫的行删除 + 文件 unlink"（`releaseUncommittedBlob` 清理失败提交，以及 GC）与并发写相同内容之间存在
毫秒级窗口：行删除成功后、unlink 之前，一个并发的失败提交 + 同内容上传可能恰好复用该文件，从而留下"objects
行存在但文件已被删"的对象。受支持拓扑下窗口极小；**恢复方式是重新上传该对象**（内容寻址，重新上传会补回
文件），无需人工修库。前提仍是每个可写 blob 目录只跑一个副本。

### 5.7 手动触发与报告

`POST /api/v1/admin/gc`（需要 `manage:any`）同步执行一轮并返回报告：

```json
{"blobs_deleted":0,"bytes_deleted":0,"uploads_deleted":0,
 "idempotency_deleted":0,"orphan_files_deleted":0,"orphan_bytes_deleted":0,"errors":0}
```

单轮内各步骤的局部错误不会让请求变成 5xx：响应仍是 200，`errors` 计数非零，细节在日志里。

## 6. API 参考

### 6.1 通用约定

- **认证**：除公开路由（`/healthz`、`/readyz`、`/presign/*`）外必须携带 `Authorization: Bearer <JWT>`；
  失败、缺失或过期都是 `401 invalid_token`。
- **错误体**：`application/problem+json`（RFC 9457）：
  `{"type":"about:blank","title":"...","status":<code>,"detail":"<稳定错误码>","instance":"<request id>"}`；
  403 额外带 `reason`（尝试过的权限键）。未知路径 `404 invalid_request`，方法不允许 `405 invalid_request`。
- **请求体**：JSON 解析上限 1 MiB，超限 `413 payload_too_large`；解析失败或字段非法 `400 invalid_request`。
- **分页**：`?limit=`（默认 100，最大 1000，0/缺省取默认，负数或非法 400）；`?cursor=` 是不透明令牌。普通列举
  由 store 生成 `{"v":1,"s":"<scope>","c":...}`（base64url，`s` 绑定查询，跨查询复用报 400）；own+team 合并桶
  列表用 httpx 的 `{"v":1,"c":...}`（无 scope 字段，外来游标不会被判为非法）。响应
  `{"items":[...],"next_cursor":"..."}`，`next_cursor` 为空串表示最后一页。
- **幂等**：仅对 POST 生效，携带 `Idempotency-Key`（去空白后 ≤1024 字节；缺失或超长则跳过幂等）。作用域 =
  `SHA-256(raw Authorization)`，无认证头时回退客户端 IP；请求体 ≤64 KiB 才参与。同 key 同 body 重放原响应并
  带 `Idempotency-Replayed: true`；同 key 不同 body → `422 idempotency_conflict`；仍在执行 →
  `409 idempotency_in_progress`。只有 200–428 且响应体 ≤64 KiB 的响应会被保留，其余记为 dead（可重新占用）。
- **校验与元数据头**：请求可带 `X-Filehouse-SHA256`（裸小写 hex），不匹配 `422 checksum_mismatch`；响应带
  `ETag: "<sha256>"` 与裸 `X-Filehouse-SHA256`；自定义元数据用 `X-Filehouse-Meta-<name>`（名称 ≤64
  字符、HTTP token 字符集，值与名称合计 ≤2 KiB），GET/HEAD 原样回显；`?download=1` 时附加
  `Content-Disposition: attachment`（文件名为 key 的 basename）。
- **Range / 条件请求**：GET/HEAD 对象由 `http.ServeContent` 提供标准语义（`Range`、`If-*`、`206`/`304`/`416`，
  `HEAD` 只回头）。
- **对象 key 约束**：1–1024 字节；不得以 `/` 开头；不得含空段（`//`）、`.`/`..` 段或控制字符
  （0x00–0x1F、0x7F）。key 按字节原样存储，不做归一化。

### 6.2 路由表

| Method | Path | 权限 | 语义 |
| --- | --- | --- | --- |
| GET | `/healthz` | 公开 | 存活探针，恒 200 `{"status":"ok"}` |
| GET | `/readyz` | 公开 | 就绪探针，检查 PostgreSQL 与 blob 目录可写性 |
| GET | `/api/v1/buckets` | read（按 grants 过滤） | 列举可读桶，`limit`/`cursor` |
| POST | `/api/v1/buckets` | write | 建桶（owner=调用者） |
| GET | `/api/v1/buckets/{bucket}` | read | 读取桶元数据 |
| PATCH | `/api/v1/buckets/{bucket}` | write；改配额需 `manage:any` | 改描述/配额 |
| DELETE | `/api/v1/buckets/{bucket}` | delete | 删除空桶 |
| GET | `/api/v1/buckets/{bucket}/objects` | read | 列举对象，`prefix`/`limit`/`cursor` |
| PUT | `/api/v1/buckets/{bucket}/objects/{key...}` | write | 上传/覆盖对象 |
| GET / HEAD | `/api/v1/buckets/{bucket}/objects/{key...}` | read | 下载/取元数据（Range、条件请求） |
| DELETE | `/api/v1/buckets/{bucket}/objects/{key...}` | delete | 删除对象 |
| POST | `/api/v1/buckets/{bucket}/uploads` | write | 发起分片上传 |
| PUT | `/api/v1/buckets/{bucket}/uploads/{uploadID}/parts/{partNo}` | write | 上传一个分片 |
| GET | `/api/v1/buckets/{bucket}/uploads/{uploadID}` | read | 查看 upload 与已存分片 |
| POST | `/api/v1/buckets/{bucket}/uploads/{uploadID}/complete` | write | 校验分片并拼装提交 |
| DELETE | `/api/v1/buckets/{bucket}/uploads/{uploadID}` | write | 中止并清理 upload |
| POST | `/api/v1/presign` | share + read（GET/HEAD）或 share + write（PUT） | 签发预签名链接 |
| GET | `/api/v1/usage` | 任意已认证主体 | 自身用量（自数据，不走级联） |
| GET | `/api/v1/me/permissions` | 任意已认证主体 | 自身有效 grants（自数据，不走级联） |
| GET | `/api/v1/admin/stats` | `manage:any` | 平台统计 + 物理 blob 清点 |
| GET | `/api/v1/admin/quotas` | `manage:any` | 列举主体配额，`kind`/`limit`/`cursor` |
| PUT | `/api/v1/admin/quotas/{user\|team}/{id}` | `manage:any` | upsert 主体配额 |
| POST | `/api/v1/admin/gc` | `manage:any` | 手动执行一轮 GC 并返回报告 |
| GET / HEAD / PUT | `/presign/{bucket}/{key...}?sig=` | 公开（签名即凭据） | 兑换预签名链接 |

### 6.3 端点要点

**建桶** `POST /api/v1/buckets`：body `{"name","team_id","description","quota_bytes","quota_objects"}`。
`name` 必须匹配 `^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`；配额缺省时取配置的桶默认配额。写权限按"预期桶"判定
（owner=调用者、team=body 团队）。成功 `201` 返回完整 bucket 行；重名 `409 bucket_exists`。

**改桶** `PATCH /api/v1/buckets/{bucket}`：body 至少一个字段（`description`/`quota_bytes`/`quota_objects`），
改配额需额外通过 `manage:any`，返回更新后的 bucket 行。

**列举桶** `GET /api/v1/buckets`：同时持有 own 与 team 读权限时，服务把两个来源按桶名归并、去重、逐行复核，
用自己的游标翻页；其余情况按单一来源过滤。被拒绝的行不会出现在页里。

**对象上传** `PUT /api/v1/buckets/{bucket}/objects/{key...}`：直接覆盖同 key；请求体上限
`FILEHOUSE_OBJECT_MAX_BYTES`，已知 `Content-Length` 超限立即 `413 payload_too_large`。成功 `201` 返回
对象 JSON，并带 `ETag`/`X-Filehouse-SHA256` 响应头。

**对象下载** `GET|HEAD`：响应头含 `ETag`、`X-Filehouse-SHA256`、`Content-Type` 与全部元数据头；支持
Range 与条件请求。

**分片上传**：

1. `POST /api/v1/buckets/{bucket}/uploads` body `{"key","content_type","metadata","size"?}` →
   `201 {"upload_id","expires_at","part_count"}`；`size` 是可选的声明总大小，用于权限判定。
2. `PUT .../uploads/{uploadID}/parts/{partNo}`：body 为分片字节，partNo ≥ 1，单分片上限
   `FILEHOUSE_PART_MAX_BYTES`；同号重传覆盖。成功 `200` 返回 `{upload_id, part_no, size, sha256,
   created_at}`。
3. `GET .../uploads/{uploadID}`：返回 upload 详情与 `parts` 列表。
4. `POST .../uploads/{uploadID}/complete` body `{"parts":[{"part_no":1,"sha256":"..."}]}`：列表本身非法
   （`part_no < 1` 或非严格升序）返回 `400 invalid_request`；列表合法但与已存分片不一致（数量/编号/提供的
   `sha256` 不匹配）返回 `422 part_mismatch`。拼装后走与直传相同的去重与配额路径，成功 `201` 返回对象 JSON，
   并删除 upload 行与暂存目录。分片编号不要求连续。
5. `DELETE .../uploads/{uploadID}`：中止并清理，`204`。
6. 过期 upload 返回 `410 upload_expired`；upload 不属于该桶视为 `404 upload_not_found`；他人拥有的 upload
   需要额外的 `:any` 权限（upload 对 owner 私有）。

**预签名签发** `POST /api/v1/presign`：body
`{"bucket","key","method","ttl_seconds","content_type","max_bytes"}`。
`method` 只接受 `GET`/`HEAD`（需 share + read）或 `PUT`（需 share + write），两者在同一桶资源上下文判定；缺省
TTL 取 `FILEHOUSE_PRESIGN_DEFAULT_TTL`，超过 `FILEHOUSE_PRESIGN_MAX_TTL` 直接 `400 invalid_request`。
`content_type`/`max_bytes` 只对 PUT 有意义：content type 写入签名并在兑换时回写为请求头（拒绝控制字符或超长
值），`max_bytes` 钳制到对象大小上限。成功 `200` 返回 `{"url","method","bucket","key","expires_at"}`；URL
origin 优先取 `FILEHOUSE_PUBLIC_BASE_URL`，未配置时从请求推导（需保证反代不改写 Host）。

**预签名兑换** `GET|HEAD|PUT /presign/{bucket}/{key...}?sig=`：先验签，再按签名内主体的 `perm_ver` 重查当前
权限，然后对当前资源重跑级联。本地权限缓存未命中/过期（默认 2 分钟 TTL）或收到 NATS 失效事件后，`perm_ver`
不一致即拒绝；缓存条目仍在有效期内时，撤权/变更最长约 2 分钟内仍可能放行。GET 的 token 也允许 HEAD，PUT 只
接受 PUT token。签名无效/不匹配方法或对象 → `403 presign_invalid`；过期 → `410 presign_expired`；权限已变更
→ `403 insufficient_permissions`。PUT 兑换与已认证 PUT 共用同一条上传路径（去重、配额、
`X-Filehouse-SHA256`、元数据头全支持）。

**自服务**：`GET /api/v1/usage` 返回
`{"subject":{"id","kind"},"used_bytes","used_objects","quota_bytes","quota_objects","buckets":[...]}`，`buckets`
是调用者拥有的每个桶的用量行（含桶配额与主体配额），主体配额取 `quotas` 表中 `user` 类型的记录（缺失即无限）。
`GET /api/v1/me/permissions` 返回排序后的 `[!]resource:action:scope` 列表（deny 保留 `!` 前缀）。

**管理面**：`GET /api/v1/admin/stats` 返回 `Stats` 全字段（`buckets`、`objects`、`logical_bytes`、`blobs`、
`blob_bytes`、`zero_ref_blobs`、`uploads`、`expired_uploads`、`quotas`）外加 `physical_blobs`/`physical_bytes`
（遍历 blob 目录清点，最多 1,000,000 个文件，遍历中消失的文件跳过）；`GET /api/v1/admin/quotas?kind=user|team&
limit=&cursor=` 按 `(subject_kind, subject_id)` 排序；`PUT /api/v1/admin/quotas/{kind}/{id}` body
`{"max_bytes":0,"max_objects":0}`（0 = 不限，subject id 去空白后 1–256 字节）返回存储后的行；
`POST /api/v1/admin/gc` 见 §5.7。

### 6.4 错误码表

| HTTP | `detail` | 含义 / 触发点 |
| --- | --- | --- |
| 400 | `invalid_bucket_name` | 桶名不匹配语法：建桶、路径参数、预签名请求 |
| 400 | `invalid_key` | 对象 key 非法：PUT/GET/DELETE 对象、发起上传、预签名请求 |
| 400 | `invalid_request` | JSON 解析失败、参数非法（limit/负数配额/非法 method/TTL 超上限/非法 kind/cursor 非法/分片列表非法）；未知路径（404）与方法不允许（405）也用它 |
| 401 | `invalid_token` | 无/格式错误/验签失败/过期的 Bearer token |
| 403 | `insufficient_permissions` | 级联拒绝（含缓存/传输失败被 SDK 折合的拒绝）；`reason` 列出尝试过的权限键或失败原因（如 `authorization service unavailable`） |
| 403 | `presign_invalid` | 签名缺失、伪造、不匹配方法/桶/key |
| 404 | `bucket_not_found` | 桶不存在（或提交对象时桶已消失） |
| 404 | `object_not_found` | 对象不存在（普通下载与预签名下载） |
| 404 | `upload_not_found` | upload 不存在、不属于该桶，或已清理 |
| 409 | `bucket_exists` | 桶名已被占用 |
| 409 | `bucket_not_empty` | 删除的桶仍有对象 |
| 409 | `idempotency_in_progress` | 同 Idempotency-Key 的请求仍在执行 |
| 410 | `upload_expired` | upload 已过期 |
| 410 | `presign_expired` | 预签名链接已过期 |
| 413 | `payload_too_large` | JSON 体 >1 MiB、对象/分片超限、预签名 token 的 `max_bytes` 超限 |
| 413 | `quota_exceeded` | 桶配额或主体配额将超限（事务回滚，计数器不变） |
| 422 | `checksum_mismatch` | 请求头 `X-Filehouse-SHA256` 与实际内容不符 |
| 422 | `part_mismatch` | complete 提交的分片列表与已存分片不一致，或拼装时缺分片 |
| 422 | `idempotency_conflict` | 同 Idempotency-Key 携带了不同请求体 |
| 500 | `service_unavailable` | 内部错误（响应序列化、预签名签发/URL 组装失败） |
| 503 | `iam_unavailable` | 权限决策不可用：authorizer 未配置或 `Decide` 返回错误；列表接口 `Grants` 失败；预签名兑换无法拉取权限 |
| 503 | `service_unavailable` | PostgreSQL、blob 存储等依赖故障 |

`/readyz` 在依赖不可用时返回 `503 {"status":"unavailable"}`（不是 problem 文档）。

## 7. 配置

### 7.1 优先级

**CLI flag > `FILEHOUSE_*` 环境变量 > Nekostick `HOST`/`PORT` > 内置默认值**。`run -h` 列出全部 flag；
`filehouse status` 打印生效配置（DSN 密码、服务令牌、client secret 一律打码）。最小可用配置 = DSN +
teamusers base URL + （静态服务令牌或 client id/secret 二者之一）。启动前执行 `Validate()`，不满足即拒绝启动
（退出码 2）。

### 7.2 完整配置表

| 变量 | 默认值 | 含义 | 生产建议 |
| --- | --- | --- | --- |
| `FILEHOUSE_DSN` | 无（必填） | PostgreSQL 连接串（URL 或 key/value） | 独立库与最小权限角色；密码走密钥管理 |
| `FILEHOUSE_ADDR` | `127.0.0.1`（`HOST` 兜底） | 监听地址 | 只在反代后或容器网内使用；外部直达才用 `0.0.0.0` |
| `FILEHOUSE_PORT` | `8080`（`PORT` 兜底） | 监听端口；`0` 选空闲端口 | 与编排端口一致；`0` 仅用于测试 |
| `FILEHOUSE_BLOB_DIR` | `data` | `blobs/`、`tmp/`、`uploads/` 根目录 | 本地持久卷；**一个可写目录一个副本**；容量单独规划 |
| `FILEHOUSE_KEY_DIR` | `data/keys` | 预签名 HMAC 密钥目录（`presign-hmac.key`，0600，32 字节） | 与 blob 目录同级备份；密钥丢失会让未过期链接全部失效 |
| `FILEHOUSE_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` | 默认 `info`；排查时临时 `debug` |
| `FILEHOUSE_NODE_ID` | 主机名 | 日志中的节点标识 | 多实例显式设置，便于日志聚合 |
| `FILEHOUSE_PUBLIC_BASE_URL` | 空（从请求推导） | 预签名链接的绝对 origin | 反代后**必设**，如 `https://files.example.com`；不得带 query/fragment |
| `FILEHOUSE_TRUSTED_PROXIES` | 空（仅 loopback 可信） | 允许设置 `X-Forwarded-For` 的 CIDR/IP 列表 | 填入口网段；影响日志 client_ip 与幂等作用域回退 |
| `FILEHOUSE_TEAMUSERS_BASE_URL` | 无（必填） | teamusers 基址（JWKS 在 `/.well-known/jwks.json`） | 指向内网/集群地址，减少公网依赖 |
| `FILEHOUSE_TEAMUSERS_ISSUER` | 空（SDK 默认，issuer 默认 `teamusers`） | 期望的 JWT `iss` | 与 teamusers 部署一致；不一致会全体 401 |
| `FILEHOUSE_TEAMUSERS_AUDIENCE` | 空（SDK 默认） | 期望的 JWT `aud` | 同上 |
| `FILEHOUSE_TEAMUSERS_SERVICE_TOKEN` | 空 | 静态服务令牌 | 仅临时使用；不会轮换，优先 client credentials |
| `FILEHOUSE_TEAMUSERS_CLIENT_ID` | 空 | OAuth client id | 与 secret 成对配置 |
| `FILEHOUSE_TEAMUSERS_CLIENT_SECRET` | 空 | OAuth client secret | 走密钥管理，不写进镜像 |
| `FILEHOUSE_TEAMUSERS_NATS_URL` | 空 | 权限/密钥失效事件的 NATS 端点 | 需 `-tags nats` 构建；未启用则依赖缓存 TTL |
| `FILEHOUSE_TEAMUSERS_TIMEOUT` | `5s` | teamusers HTTP 调用超时 | 过大拖慢 fail-closed 返回，网络抖动大时适度上调 |
| `FILEHOUSE_TEAMUSERS_ADMIN_TOKEN` | 空 | 仅供 `register-permissions` 使用的管理员令牌 | 只在首次/升级注册时提供，不随服务长驻 |
| `FILEHOUSE_PRESIGN_DEFAULT_TTL` | `15m` | 请求省略 `ttl_seconds` 时的有效期 | 按分享场景收敛；必须 ≤ max TTL |
| `FILEHOUSE_PRESIGN_MAX_TTL` | `24h` | 预签名有效期硬上限 | 越短越安全；撤权后最长约 2 分钟（缓存 TTL）内链接可能仍可用 |
| `FILEHOUSE_OBJECT_MAX_BYTES` | `5368709120`（5 GiB） | 单对象大小上限 | 同步调整反代/客户端上限；大对象用分片 |
| `FILEHOUSE_PART_MAX_BYTES` | `268435456`（256 MiB） | 单分片大小上限 | 一般无需修改 |
| `FILEHOUSE_UPLOAD_TTL` | `24h` | 分片上传暂存有效期 | 按客户端最长断点续传时长设置 |
| `FILEHOUSE_BUCKET_DEFAULT_QUOTA_BYTES` | `0`（不限） | 新建桶默认字节配额 | 建议设非零，防止单桶吃满磁盘 |
| `FILEHOUSE_BUCKET_DEFAULT_QUOTA_OBJECTS` | `0`（不限） | 新建桶默认对象数配额 | 同上 |
| `FILEHOUSE_GC_INTERVAL` | `15m` | reaper 周期 | 大目录可放宽；磁盘紧张时缩短 |
| `FILEHOUSE_GC_GRACE` | `1h` | 零引用 blob / 孤儿文件宽限期 | 必须显著大于最长上传耗时；调小加快回收但增加在途风险 |
| `FILEHOUSE_IDEMPOTENCY_TTL` | `24h` | `Idempotency-Key` 重放窗口 | 覆盖客户端重试窗口即可；reaper 另有固定 24h 清理 |

其他环境变量：`HOST`/`PORT` 仅在对应 `FILEHOUSE_*` 未设置时兜底；`FILEHOUSE_TEST_PG` 仅用于集成测试
（§9）；`FILEHOUSE_TEAMUSERS_ADMIN_TOKEN` 之外的所有变量都可用同名小写 flag 覆盖（如 `-dsn`、`-port`、
`-teamusers-client-id`、`-gc-grace`、`-trusted-proxies`）。

## 8. 运维手册

### 8.1 健康检查语义

`GET /healthz` 不检查任何依赖，只要进程能响应就 200，适合 liveness/自动重启判断。`GET /readyz` 在 5 秒超时内
执行 `SELECT 1`（PostgreSQL）与 blob 目录可写探测，全部通过返回 `200 {"status":"ready"}`，否则
`503 {"status":"unavailable"}` 并记录失败项日志，适合流量门控与告警，不代表需要重启进程。

### 8.2 启动、迁移与升级

启动顺序：校验配置 → 连接并 ping PostgreSQL → advisory lock 下执行内嵌 goose 迁移 → 打开 blob 目录（建目录 +
可写探测）→ 构建 IAM authorizer → 加载/创建预签名密钥 → 启动 GC goroutine → 监听端口。任一步失败即退出
（配置错误退出码 2，其余 1）。

`doctor` 重新检查数据库、迁移、blob 目录、密钥目录与 teamusers JWKS 连通性（IAM 未配置时打印 SKIP），适合
升级后与故障时使用。升级流程：替换二进制 → 重启（迁移自动应用）→ 用 `doctor`、`/healthz`、`/readyz` 与一次
上传/下载冒烟确认。迁移幂等，多实例同时启动由 advisory lock 串行化。停机时 SIGINT/SIGTERM 后最多 10 秒排空
在途请求；未完成请求可能被中断，客户端应使用幂等键重试。

### 8.3 备份与一致性

PostgreSQL 行与 blob 目录是同一份状态的两半，**必须一起备份/恢复**，只恢复其一会得到无法下载的对象。建议先取
数据库快照再备份 blob 目录（或停机后一起备份），并同时备份 `FILEHOUSE_KEY_DIR`（否则所有未过期预签名链接
失效）。恢复后用 `GET /api/v1/admin/stats` 对比 `logical_bytes`/`blobs`/`physical_blobs` 观察行与文件是否对齐，
零引用与孤儿由 GC 后续对账。

### 8.4 容量与配额管理

磁盘需求 ≈ `blobs/` 物理占用 + `tmp/` 在途 + `uploads/` 暂存 + grace 窗口内待回收内容；去重让物理占用通常小于
逻辑用量之和。`GET /api/v1/admin/stats` 给出逻辑/物理两套数字与 `zero_ref_blobs`、`expired_uploads`，可用于
核对回收进度；`POST /api/v1/admin/gc` 立即回收一轮。配额两层：桶级（建桶时或 `PATCH` 设置，改配额需
`manage:any`）与主体级（`PUT /api/v1/admin/quotas/{user|team}/{id}`，0 = 不限）。超限写入返回
`413 quota_exceeded` 且不产生任何计数变化。

### 8.5 日志与 request id

输出为单行 JSON（`slog`，stdout），公共字段 `service`、`node_id`、`version`；访问日志字段 `method`、`path`、
`status`、`bytes`、`duration_ms`，解析到 IP 时带 `client_ip`，以及 `request_id`。5xx 以 `error` 级别输出，
其余 `info`。request id 优先沿用合法的入站 `X-Request-ID`（1–128 个可打印 ASCII），否则生成新 id；响应头回写
`X-Request-ID`，problem 文档的 `instance` 也是它，排障时用它串联访问日志与错误日志。密钥与令牌不落日志：认证
失败日志中的原始 token 被替换为 `[redacted]`；`status` 输出对 DSN 密码、服务令牌与 client secret 打码。

### 8.6 限流

**本服务未实现请求限流**（没有令牌桶、并发闸门或按主体速率限制）。防护依赖反向代理/入口的限流与 teamusers 的
判定延迟；如需速率限制，请在入口层实施。

### 8.7 故障排查

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| `/readyz` 503 | PostgreSQL 不可达或 blob 目录不可写 | 查 `doctor`、DSN、目录权限与磁盘空间 |
| 全部请求 401 `invalid_token` | issuer/audience 与 teamusers 不一致，或 JWKS 不可达 | 核对 `TEAMUSERS_ISSUER/AUDIENCE` 与网络；`doctor` 检查 JWKS |
| 403 `insufficient_permissions` | 主体缺少对应权限键 | 看响应 `reason` 中的尝试键，在 teamusers 侧补授权 |
| 403 `presign_invalid` | 链接被截断/篡改、方法或对象不匹配 | 重新签发；确认 `sig` 查询参数完整 |
| 410 `presign_expired` | 链接过期 | 重新签发或调大 TTL 上限 |
| 预签名链接指向内网地址 | `PUBLIC_BASE_URL` 未配置且反代改写 Host | 设置 `FILEHOUSE_PUBLIC_BASE_URL` |
| 413 `quota_exceeded` | 桶/主体配额已满 | 提高配额或删除对象；删除后逻辑用量立即释放 |
| 422 `checksum_mismatch`/`part_mismatch` | 客户端摘要错误 / 分片集合不一致 | 核对分片编号与 sha256 后重试 |
| 上传失败后磁盘不降 | 内容仍在 grace 窗口内或为孤儿待扫 | 看 stats 与 GC 日志；必要时缩短 grace 或手动触发 GC |
| 大量 403 `insufficient_permissions` 且 reason 含 `authorization service unavailable` | teamusers 不可达或服务凭据缺失/过期 | 检查 client id/secret、网络；静态令牌模式确认未过期 |
| 503 `iam_unavailable` | authorizer 未配置、`Decide` 返回错误、`Grants` 失败或兑换取权限失败 | 查看日志中的具体错误；确认服务凭据与 teamusers 可达 |

## 9. 测试

```sh
# 单元测试：集成测试在无门控变量时自动跳过
go test ./...

# 完整 HTTP 级集成测试（需要可清空的 PostgreSQL 库）
FILEHOUSE_TEST_PG='postgres://postgres:postgres@127.0.0.1:5432/filehouse_test?sslmode=disable' \
  go test ./test/... -count=1
```

`FILEHOUSE_TEST_PG` 门控 `test/`；未设置时整个包跳过，`go test ./...` 在没有 PostgreSQL 的机器上保持
绿色。**该库会被清空**：每个用例执行前 truncate 所有表，并使用临时 blob 目录与临时预签名密钥，绝不要指向
生产库。`internal/iamfixture` 提供真实签名的假 teamusers（Ed25519 JWKS/JWT、权限缓存、deny 与条件判定、
client-credentials、权限注册），测试断言的是可观察 HTTP 行为而不是内部接线。集成用例覆盖：未认证拒绝、无关
权限拒绝、scope 级联、对象往返（Range/ETag/校验和）、内容去重与 GC 回收、分片上传全流程、桶配额、预签名全流程
（含 perm_ver 变更与缓存失效后的拒绝）、游标分页、幂等重放、管理面权限、孤儿回收、孤儿扫描跨页推进。

## 10. 已知限制与边界

- **无审计日志**：只有结构化请求日志，没有访问审计、篡改证明或审计保留策略；不要当合规审计使用。
- **无版本与回收站**：对象删除即从命名空间消失，覆盖写不保留旧版本。
- **单副本约束**：受支持拓扑是每个可写 blob 目录一个副本；多副本需共享 blob 目录，而共享目录会放大 §5.6 的
  并发删除竞态并且未经验证。
- **并发删除竞态**：删除路径与"失败提交 + 同内容并发上传"交错的毫秒级窗口可产生"行在文件亡"的对象；恢复方式
  是重新上传该对象。
- **GC 是渐进式对账**：零引用 blob 需等 grace 结束，孤儿扫描每轮最多 5000 个文件并按游标推进，超大目录或持续
  写入时回收会滞后；磁盘占用可能长期高于逻辑用量。
- **幂等重放有边界**：仅 POST、key ≤1024 字节、请求体 ≤64 KiB；只有 200–428 且响应 ≤64 KiB 会被重放，其余
  响应按 dead 处理（可重新执行）。reaper 对幂等记录的清理保留期固定 24h，与 `FILEHOUSE_IDEMPOTENCY_TTL`
  无关。
- **预签名与权限版本绑定**：兑换时按 `perm_ver` 重查权限——本地缓存未命中/过期（默认 2 分钟）或收到 NATS 失效
  事件后，撤权/变更即被拒；缓存命中期间最长约 2 分钟内仍可能放行。签名密钥丢失或更换会让所有未过期链接失效。
- **未实现请求限流**（§8.6）；服务自身不做 TLS 终止，需由反向代理提供。
- **去重与配额口径**：配额按逻辑用量（对象数与字节数）而非物理磁盘占用，无法用配额限制物理文件数量。
- **分片上传的 `size` 声明只参与授权判定**，最终大小以实际拼装结果为准；分片编号必须升序且与已上传集合完全
  一致，但可以不连续。
- **元数据上限 2 KiB**（名称与值合计）；key 原样存储，不做 Unicode 归一化或大小写折叠。
- **未暴露的调优项**：GC 孤儿扫描页大小（`OrphanScanLimit`，默认 5000）没有对应的环境变量或 flag。
