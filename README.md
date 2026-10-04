# nsc-filehouse

Nekostick 机队的对象存储微服务：元数据存放在 PostgreSQL，对象字节存放在本地内容寻址
（content-addressed）的 blob 目录。服务本身不持有身份，认证与授权全部委托给
[teamusers](https://crazy4chicken.github.io/nsc-teamusers/) IAM 服务。

## 架构

```mermaid
flowchart LR
    C[Client / SDK] -->|Bearer JWT| F[filehouse]
    C -->|presigned URL| F
    F -->|JWT 验签 · 权限判定| T[teamusers IAM]
    F -->|元数据| P[(PostgreSQL)]
    F -->|blob 文件| B[(本地 blob 目录)]
```

- 身份来自 Bearer access token，由 teamusers 的 JWKS 验签；token 只证明身份，不携带权限。
- 每个请求都做一次 `filehouse:<verb>:<scope>` 级联判定，权限数据来自 teamusers 并在本地缓存
  （默认 2 分钟），缓存未命中或过期才回源；判定失败一律 fail-closed。
- 相同 SHA-256 的内容只落盘一份，数据库行通过 refcount 引用计数，实现内容去重。

## 核心能力

- **对象与桶**：桶按 `owner` / `team` 归属；对象按 `bucket/key` 寻址，支持覆盖写、前缀列举与
  Range 下载。
- **分片上传**：initiate / put part / complete / abort 的完整 multipart 流程，分片先进入暂存区，
  complete 时按序拼装并走与直传相同的配额与去重路径。
- **预签名直传直下**：`POST /api/v1/presign` 签出 HMAC-SHA256 链接，浏览器或第三方可凭链接
  GET/HEAD 下载或用 PUT 直传，无需携带 access token。
- **SHA-256 内容去重**：ETag 与 `X-Filehouse-SHA256` 都是内容的 SHA-256；重复内容共享同一
  个 blob 文件。
- **桶 / 主体配额与用量**：桶级 `quota_bytes`/`quota_objects`，以及按 user/team 的主体级配额，
  在写入事务内原子校验；`GET /api/v1/usage` 返回自身用量。
- **与 teamusers 的鉴权对接**：JWT 验证走 teamusers JWKS；权限目录（permission catalog）由
  `register-permissions` 幂等注册；服务自身调用 teamusers 使用 client-credentials 自动刷新
  （也支持静态服务令牌）。
- **游标分页**：列举接口返回不透明 `next_cursor`（按 name/key 严格递增定位），并发增删不会重复
  返回同一条目。
- **幂等重试**：POST 携带 `Idempotency-Key` 可安全重试，命中时回放原响应并标记
  `Idempotency-Replayed: true`。

## 快速开始

### 环境要求

- Go 1.26+（构建本服务）
- PostgreSQL 16+（空库；启动时自动应用内嵌迁移）
- 一个可访问的 teamusers 地址，以及服务凭据（client id/secret 或静态服务令牌）
- 首次使用前，需要 teamusers 管理员令牌执行一次权限目录注册

### 构建

```sh
go build -o filehouse ./cmd/filehouse
# 需要 NATS 失效事件时：go build -tags nats -o filehouse ./cmd/filehouse
```

### 最小环境变量启动

```sh
export FILEHOUSE_DSN='postgres://filehouse:filehouse@127.0.0.1:5432/filehouse?sslmode=disable'
export FILEHOUSE_TEAMUSERS_BASE_URL='https://iam.example.com'
export FILEHOUSE_TEAMUSERS_CLIENT_ID='filehouse'
export FILEHOUSE_TEAMUSERS_CLIENT_SECRET='********'

# 一次性：把 filehouse 权限目录注册进 teamusers（幂等，可重复执行）
FILEHOUSE_TEAMUSERS_ADMIN_TOKEN='********' ./filehouse register-permissions

./filehouse run              # 默认子命令；-h 查看全部 flag（flag 优先于环境变量）
```

也可以先用 `./filehouse status` 查看打码后的生效配置，用 `./filehouse doctor` 检查
数据库、迁移、目录与 teamusers 连通性。

### 验证

```sh
curl -fsS http://127.0.0.1:8080/healthz   # {"status":"ok"}         进程存活
curl -fsS http://127.0.0.1:8080/readyz    # {"status":"ready"}      PostgreSQL 与 blob 目录可用
# 依赖不可用时 /readyz 返回 503 {"status":"unavailable"}
```

## 典型用法

以下示例假设 `BASE=http://127.0.0.1:8080`。

**1. 获取访问令牌**

用户登录 / 刷新由 teamusers 负责，见 [teamusers 文档](https://crazy4chicken.github.io/nsc-teamusers/)；
本服务不签发、不刷新令牌。服务身份可使用 client-credentials：

```sh
TOKEN=$(curl -s -X POST "$FILEHOUSE_TEAMUSERS_BASE_URL/auth/client-credentials" \
  -H 'content-type: application/json' \
  -d '{"client_id":"...","client_secret":"..."}' | jq -r .access_token)
```

**2. 建桶**

```sh
curl -s -X POST "$BASE/api/v1/buckets" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"reports","team_id":"core"}'
```

**3. 上传对象**

```sh
SHA=$(sha256sum report.pdf | cut -d' ' -f1)
curl -s -X PUT "$BASE/api/v1/buckets/reports/objects/2026/report.pdf" \
  -H "Authorization: Bearer $TOKEN" -H "X-Filehouse-SHA256: $SHA" \
  --data-binary @report.pdf
```

**4. 下载（含 Range 与元数据）**

```sh
curl -sI "$BASE/api/v1/buckets/reports/objects/2026/report.pdf" \
  -H "Authorization: Bearer $TOKEN"          # 响应含 ETag: "<sha256>"
curl -s -r 0-1023 "$BASE/api/v1/buckets/reports/objects/2026/report.pdf" \
  -H "Authorization: Bearer $TOKEN" -o head.bin
```

**5. 预签名分享**

```sh
curl -s -X POST "$BASE/api/v1/presign" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"bucket":"reports","key":"2026/report.pdf","method":"GET","ttl_seconds":600}'
# → {"url":".../presign/reports/2026/report.pdf?sig=...","method":"GET",...}

curl -s "<上一步返回的 url>" -o report.pdf     # 无需 Authorization 头
# method=PUT 的链接可直接上传；ttl_seconds 省略时使用配置的默认有效期
```

桶名必须匹配 `^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`；对象 key 长度 1–1024 字节，不得以 `/` 开头，
不得包含空段、`.`/`..` 段或控制字符。

## 文档

- 在线文档站点：[https://crazy4chicken.github.io/nsc-filehouse/](https://crazy4chicken.github.io/nsc-filehouse/)
  — 使用指南（快速开始、上传下载、权限模型）与完整 API 参考。
- [docs/manual.md](docs/manual.md) — 技术手册：架构与请求时序、鉴权与权限模型、数据模型与事务
  不变量、blob 布局与 GC、完整 API 参考、完整配置表、运维与故障排查、测试、已知限制。
- [docs/deployment.md](docs/deployment.md) — 部署说明：Nekostick compose 示例、反向代理、备份与升级。

## 限制与注意事项

- 受支持拓扑是**一个可写 blob 目录对应一个副本**；多副本需要共享同一 blob 目录，该形态未经验证，且
  blob 目录必须是本地持久卷。
- ETag 与 `X-Filehouse-SHA256` 是 SHA-256（ETag 带引号），不是 MD5。
- 单对象大小上限默认 5 GiB（`FILEHOUSE_OBJECT_MAX_BYTES`），单分片默认 256 MiB。
- 不提供审计日志，也没有版本管理与回收站；删除即从命名空间移除。
- 密钥与令牌不写入日志，`status` 输出的配置中密钥一律打码。
- 删除对象立即释放逻辑配额，但 blob 文件由 GC 在 grace 窗口后回收，磁盘占用会滞后下降。
- 预签名链接的签名密钥保存在 `FILEHOUSE_KEY_DIR`，密钥丢失或更换会让所有未过期链接失效。
