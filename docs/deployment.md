# 部署说明

`nsc-filehouse` 是 Nekostick 舰队中的一个受监督微服务：Nekostick（经由
[svchost](https://github.com/crazy4chicken/nekostick-svchost) 扩展）以子进程方式启动它，
注入租约监听地址、采集日志、执行健康检查并负责重启；本仓库只提供静态二进制，
不提供独立的运行时打包。部署由三部分组成：

| 组件 | 归属 | 说明 |
| --- | --- | --- |
| `filehouse` 进程 | 本文档 | 本服务，静态 Linux 二进制，由 svchost 监督 |
| PostgreSQL 16+ | 外部依赖 | 元数据库；启动时自动执行内嵌迁移 |
| teamusers IAM | 舰队既有服务 | 令牌签发与授权判定；预置在 compose 文档中一并下发 |

> 本文档是**部署说明**。完整的权限模型、API 参考、配置表与数据模型见
> [技术手册](/manual)；面向使用者的简介与快速上手见 [README](https://github.com/crazy4chicken/nsc-filehouse/blob/main/README.md)。

## 1. 前置准备

### 1.1 PostgreSQL

创建一个空数据库和一个可执行迁移（DDL）的部署角色。服务启动时会在 advisory lock
保护下自动应用 `migrations/` 中的内嵌迁移，因此部署角色需要该库的建表权限：

```sh
createuser --pwprompt filehouse
createdb --owner=filehouse filehouse
```

连接串建议使用 `sslmode=require` 或更严格模式（跨主机访问时）。迁移是幂等的：
重复启动只会报告 `no pending migrations`。

### 1.2 teamusers 侧准备

`filehouse` 自身不管理用户，需要先在 teamusers 上完成三件事。以下命令假定
`IAM` 指向 teamusers 的对外基址、`ADMIN_TOKEN` 是一个持有 `iam:users:any`、
`iam:permissions:any`、`iam:roles:any`、`iam:bindings:any`（或 `iam:*:any`）的管理员访问令牌。

**(a) 建一个服务账号并签发 client credentials**（供本服务调用 `/authz/*`）：

```sh
# 1. 建服务账号用户（不带密码）
SERVICE_USER_ID=$(curl -sS -X POST "$IAM/users/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"filehouse-svc","display_name":"Filehouse service"}' | jq -r .id)

# 2. 生成服务凭据（client_secret 只返回一次，请存入密钥设施）
curl -sS -X POST "$IAM/users/$SERVICE_USER_ID/credentials" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"service"}'
```

**(b) 注册本服务的权限目录**（13 个键，幂等 upsert）：

```sh
export FILEHOUSE_TEAMUSERS_BASE_URL="$IAM"
./filehouse register-permissions --token "$ADMIN_TOKEN"
```

**(c) 给业务用户/团队建角色并绑定权限**。权限键为
`filehouse:<read|write|delete|share>:<own|team|any>` 与 `filehouse:manage:any`，
语义见[技术手册的权限章节](/manual)。

```sh
ROLE_ID=$(curl -sS -X POST "$IAM/roles/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"filehouse-user"}' | jq -r .id)

curl -sS -X PUT "$IAM/roles/$ROLE_ID/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"permissions":["filehouse:read:own","filehouse:write:own","filehouse:delete:own","filehouse:share:own"]}'

curl -sS -X POST "$IAM/bindings/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role_id":"'$ROLE_ID'","subject_kind":"user","subject_id":"<业务用户 ID>"}'
```

**(d) 对齐令牌受众**：teamusers 用 `TEAMUSERS_TOKEN_AUDIENCE` 决定签发令牌的 `aud`，
本服务用 `FILEHOUSE_TEAMUSERS_AUDIENCE` 校验它；两者必须一致（默认都是
`teamusers`）。团队内其他服务同理。

## 2. 构建与发布

手动构建发布产物：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -tags nats \
  -ldflags '-s -w -X main.version=v0.1.0' \
  -o filehouse ./cmd/filehouse
```

或推送一个 `v*` 标签，由 [release workflow](https://github.com/crazy4chicken/nsc-filehouse/blob/main/.github/workflows/release.yml) 自动构建并发布
svchost 兼容资产 `filehouse_<version>_<arch>.zip`（`x64`、`arm64`），入口二进制
`filehouse` 位于 ZIP 根目录；每个资产的 SHA-256 会写进该次运行页的 Summary，可直接抄进
compose 模板的 `sha256`。`v0.1.0` 已按此流程发布（见 §3 模板中的摘要）：

```sh
git tag v0.1.0 && git push origin v0.1.0
```

`-tags nats` 会把 teamusers SDK 的权限失效事件订阅编译进二进制；不带该标签时
设置 `FILEHOUSE_TEAMUSERS_NATS_URL` 只会产生一条警告，权限缓存退化为按 TTL 过期。

## 3. svchost compose 完整模板

下面是一份可直接使用的 compose 配置（方言见 svchost 的
[compose 参考](https://github.com/crazy4chicken/nekostick-svchost/blob/main/docs/compose.md)）。
它同时声明 `teamusers` 与 `filehouse` 两个服务，二者共享同一份租约命名空间；
若你的团队已经有运行中的 teamusers，把 `filehouse` 的
`FILEHOUSE_TEAMUSERS_BASE_URL` 改成它的实际地址、并删掉 `teamusers` 服务即可。

```yaml
strictSources: true
serviceScope: global
services:
  teamusers:
    source:
      # 推送 v* 标签后由 release workflow 产出 teamusers_<version>_<arch>.zip。
      # 这里 pin 的是已发布的 v0.2.1，摘要取自 GitHub release API：
      #   x64   c15342405ac6bda366837ab8c446d0986ab6ae5f33cc149338bcf183f08d25d6
      #   arm64 153b3f087e1906cf01b60db68d66f1faf55d9eab912daa095946f1d7e252e8d9
      release: "github:crazy4chicken/nsc-teamusers@v0.2.1"
      sha256: "c15342405ac6bda366837ab8c446d0986ab6ae5f33cc149338bcf183f08d25d6"
    args: ["run"]
    env:
      TEAMUSERS_CONNECTION_STRING: "postgres://teamusers:<password>@10.0.0.2:5432/teamusers?sslmode=require"
      TEAMUSERS_KEY_DIR: /var/lib/teamusers/keys
      TEAMUSERS_NODE_ID: teamusers
      TEAMUSERS_TOKEN_AUDIENCE: nekostick
      TEAMUSERS_LOG_LEVEL: info
    start: eager        # 鉴权在舰队关键路径上，必须随宿主一起起来
    restart: on-failure
    health:
      type: http
      path: /healthz
      timeout: 5s
    route:
      prefix: /iam
      strip: true       # /iam/auth/login 到达子进程时是 /auth/login

  filehouse:
    source:
      # v0.1.0 已发布；下面是两个架构资产在 GitHub release API 上的真实摘要：
      #   x64   filehouse_0.1.0_x64.zip   57a6c9c9b798fa22fadcc2b614f94b2c7395da5dde692d2737f19b9e1ead8c2c
      #   arm64 filehouse_0.1.0_arm64.zip 58c7b1dc778ef19563cf6a9dd220db3d0e582d9486ec53e885868fd9788cd273
      # 后续版本：推 v* 标签让 release workflow 发布资产，摘要见该次运行的 Summary；
      # 或本地核对：
      #   curl -fSL -o fw.zip \
      #     https://github.com/crazy4chicken/nsc-filehouse/releases/download/v0.1.0/filehouse_0.1.0_x64.zip
      #   sha256sum fw.zip
      release: "github:crazy4chicken/nsc-filehouse@v0.1.0"
      sha256: "57a6c9c9b798fa22fadcc2b614f94b2c7395da5dde692d2737f19b9e1ead8c2c"
      # 还没有 release 时，可先用本地路径起步：
      # path: /opt/filehouse/filehouse
    args: ["run"]
    env:
      FILEHOUSE_DSN: "postgres://filehouse:<password>@10.0.0.2:5432/filehouse?sslmode=require"
      FILEHOUSE_BLOB_DIR: /var/lib/filehouse/blobs
      FILEHOUSE_KEY_DIR: /var/lib/filehouse/keys
      FILEHOUSE_NODE_ID: filehouse
      FILEHOUSE_LOG_LEVEL: info
      # 对外基址，决定预签名 URL 指向哪里；必须包含路由前缀（见 §5）
      FILEHOUSE_PUBLIC_BASE_URL: "https://files.example.com/files"
      # 同属本 compose 文档时，用跨服务模板引用 teamusers 的租约地址
      FILEHOUSE_TEAMUSERS_BASE_URL: "http://${HOST@teamusers}:${PORT@teamusers}"
      FILEHOUSE_TEAMUSERS_ISSUER: teamusers
      FILEHOUSE_TEAMUSERS_AUDIENCE: nekostick
      FILEHOUSE_TEAMUSERS_CLIENT_ID: filehouse-svc
      FILEHOUSE_TEAMUSERS_CLIENT_SECRET: "<服务凭据 client_secret>"
      # 可选：编译进 nats 支持后开启权限缓存失效订阅
      FILEHOUSE_TEAMUSERS_NATS_URL: ""
    start: eager        # 启动即执行迁移并预热，避免首个请求承担建表耗时
    restart: on-failure
    health:
      type: http
      path: /healthz
      timeout: 5s
    route:
      prefix: /files
      strip: true       # /files/api/v1/... 到达子进程时是 /api/v1/...
```

要点：

- **不要把 `HOST`/`PORT` 写进 `args` 或 `env`**：宿主每次启动都会注入自己的租约值，
  本服务按 `FILEHOUSE_ADDR`/`FILEHOUSE_PORT` → `HOST`/`PORT` → 默认值的顺序解析，
  留空即表示绑定租约。
- **服务 CWD 是 svchost 的 service root，不是资产目录**，因此 `FILEHOUSE_BLOB_DIR`、
  `FILEHOUSE_KEY_DIR` 必须写成绝对路径。
- `${HOST@teamusers}:${PORT@teamusers}` 读取目标服务运行时的租约地址；若 teamusers 由
  另一份 compose 文档或另一台主机托管，改用它的固定地址（如 `http://10.0.0.2:8099`）。
- `strictSources: true` 要求每个来源显式声明 `sha256`。一个摘要只对应一个架构的 ZIP：
  混合架构节点请去掉 `strictSources`（lock 仍会记录本节点首次下载的摘要），或按架构
  拆成多份 `serviceScope: document` 配置。
- 密钥（DSN 口令、`client_secret`）在宿主侧是明文存储的，按密钥设施的要求限制配置读权限；
  不要提交到版本库，也不要写进日志或示例。
- `route.prefix` + `strip: true` 与 `ForwardingMode=Strip` 等价。本服务的路由是根相对的，
  前缀由宿主机剥掉，因此**不要**关闭 `strip`，除非服务就挂在站点根路径。

## 4. 首次启动与验证

```sh
# 配置自检：打印脱敏后的生效配置
./filehouse status

# 环境诊断：数据库连通性、迁移版本、目录可写性、teamusers 可达性（JWKS）
./filehouse doctor

# 权限目录注册（幂等，可在任意时刻重跑）
./filehouse register-permissions --token "$ADMIN_TOKEN"
```

启动后依次确认（地址取日志里 `HTTP server serving` 那一行的 `addr`；本地 standalone 默认
`127.0.0.1:8080`，受监督子进程则是宿主注入的租约端口）：

```sh
curl -fsS "http://$ADDR/healthz"   # {"status":"ok"}      进程存活
curl -fsS "http://$ADDR/readyz"    # {"status":"ready"}   PostgreSQL + blob 目录可用
```

冒烟（`$TOKEN` 由 teamusers 签发，可以是用户令牌或服务令牌）：

```sh
curl -sS -X POST https://files.example.com/files/api/v1/buckets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"smoke"}'

printf 'hello' | curl -sS -X PUT \
  https://files.example.com/files/api/v1/buckets/smoke/objects/hello.txt \
  -H "Authorization: Bearer $TOKEN" --data-binary @-

curl -sS https://files.example.com/files/api/v1/buckets/smoke/objects/hello.txt \
  -H "Authorization: Bearer $TOKEN"
```

## 5. 路由与转发

服务内部路由是根相对的：`/healthz`、`/readyz`、`/presign/*`、`/api/v1/*`。外部前缀由
宿主机剥离。两个与转发相关的约定：

- **`FILEHOUSE_PUBLIC_BASE_URL` 必须是对外可达的完整前缀**（例如
  `https://files.example.com/files`），否则 `POST /api/v1/presign` 生成的链接会指向内网
  租约地址。留空时服务会用请求的 scheme + Host 推导，仅适合受信任代理会覆写 Host 的场景。
- **预签名链接同样经过前缀**：兑换路径是 `/presign/{bucket}/{key}?sig=...`，外部形态为
  `https://files.example.com/files/presign/...`；分享的链接必须能从外部直接访问。

公开面只需要 `/presign/*`（签名即凭证）与两个健康检查端点；`/api/v1/*` 一律要求
`Authorization: Bearer <令牌>`。

## 6. 监听租约、健康检查与日志

- 宿主注入的 `HOST`/`PORT` 即是本进程的监听地址；日志中的 `HTTP server serving` 记录了
  实际生效的地址，可用于关联租约。`FILEHOUSE_PORT=0` 仅推荐本地开发（随机端口）。
- 启动与稳态健康检查都用 **HTTP `/healthz`**：它不查询任何依赖，永远返回 200。
  `/readyz` 额外验证 PostgreSQL（`SELECT 1`）与 blob 目录可写性，返回 503 时不代表进程
  需要重启，可用于流量门控或告警。
- 日志是单行 JSON（`slog`），字段含 `service`、`node_id`、`version`、`request_id`；
  访问日志含 `method`、`path`、`status`、`bytes`、`duration_ms`、`client_ip`。
  令牌、`client_secret`、DSN 口令与预签名 HMAC 密钥都不会出现在日志或 `status` 输出中。

## 7. 信任代理与客户端地址

`X-Forwarded-For` 仅在直连 peer 是 loopback 或落在 `FILEHOUSE_TRUSTED_PROXIES`
（逗号分隔的 CIDR/IP）内时被采信，且从右向左跳过可信跳数、取第一个不可信地址；其余
情况忽略该头。宿主侧的反向代理必须**覆写**而不是追加客户端自带的 `X-Forwarded-For`，
否则幂等键作用域与日志中的 `client_ip` 可被伪造。

## 8. TLS 与关停

本进程不终止 TLS，证书与外部入口由反向代理负责；Nekostick 边界内只走明文 HTTP。
收到 `SIGTERM` 后服务停止接受新连接，并在 10 秒内排空在途请求；宿主应先启动新实例、
通过 `/healthz` 后切换转发，再向旧实例发送 `SIGTERM`，排空期间不要再转发流量。

## 9. 备份、升级与容量

- **备份必须同时覆盖 PostgreSQL 与 `FILEHOUSE_BLOB_DIR`**：元数据行与磁盘上的
  内容寻址文件是一套状态，只恢复其中之一会得到无法下载的对象。推荐先备份数据库快照，
  再备份 blob 目录（或停机后一起备份）。
- **升级**：替换二进制/资产摘要 → 启动新实例（迁移自动执行）→ `doctor` 与 `/healthz`
  通过 → 切换转发 → 排空旧实例。迁移只前进不回退，回滚二进制不能回滚 schema。
- **副本与目录**：一个可写 blob 目录同一时刻只应由一个副本写入；需要横向扩展时，
  为每个副本准备独立目录并接受"目录内去重"的边界，或引入共享文件系统。
- **容量**：去重让物理占用小于逻辑用量，配额按逻辑字节计。定期查看
  `GET /api/v1/admin/stats` 的 `physical_blobs`/`physical_bytes` 与
  `logical_bytes` 的差距；`POST /api/v1/admin/gc` 可手动触发一次回收。
  `FILEHOUSE_GC_GRACE` 决定孤儿文件与零引用 blob 的保留窗口，窗口越长越能保护
  在途写入，但磁盘回收越慢。
- **配额**：桶级配额写入桶行，主体级配额（用户/团队）经 advisory lock 串行化，均在
  写事务内校验；调整配额用 `PUT /api/v1/admin/quotas/{user|team}/{id}`。

## 10. 排障

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| 启动即退出，日志 `either a teamusers service token or a client id with client secret is required` | 未配置服务凭据 | 配置 `FILEHOUSE_TEAMUSERS_CLIENT_ID` + `_CLIENT_SECRET`（推荐），或临时用 `_SERVICE_TOKEN` |
| 请求返回 `401 invalid_token` | 令牌过期、`aud`/`iss` 不匹配、JWKS 不可达 | 核对 `FILEHOUSE_TEAMUSERS_AUDIENCE`/`_ISSUER` 与 teamusers 的 `TEAMUSERS_TOKEN_AUDIENCE`；`doctor` 会检查 JWKS 可达性 |
| 请求返回 `403 insufficient_permissions` | 角色未绑定对应权限键；或权限缓存未命中且 teamusers 不可达/服务凭据失效（此时 `reason` 含 `authorization service unavailable`） | 前者按 `reason` 列出的权限键在 teamusers 侧补绑定；后者检查 `FILEHOUSE_TEAMUSERS_BASE_URL` 与 client_secret，`doctor` 的 `iam` 行给出结论 |
| 请求返回 `503 iam_unavailable` | 授权组件不可用：authorizer 未就绪、列举桶或 `/api/v1/me/permissions` 查询权限失败、预签名兑换时无法读取权限 | 检查 teamusers 连通性与服务凭据；`doctor` 的 `iam` 行给出结论 |
| `/readyz` 返回 503 | PostgreSQL 不可用或 blob 目录不可写 | 检查 DSN、连接数与目录权限/磁盘空间 |
| 预签名链接指向 `127.0.0.1` 或租约端口 | `FILEHOUSE_PUBLIC_BASE_URL` 未配置 | 配置为外部带前缀的基址（见 §5） |
| 磁盘占用持续增长 | 在途 grace 内的孤儿、未达回收窗口的零引用 blob、或被拒绝写入的残留 | 查看 `/api/v1/admin/stats` 与 GC 报告；必要时缩短 `FILEHOUSE_GC_GRACE`/`FILEHOUSE_GC_INTERVAL` |
| 上传返回 `413 quota_exceeded` | 桶或主体配额已满 | 提高配额或删除对象；是哪一级配额、上限与当前用量写在服务端日志里（响应体只带稳定错误码） |
| 分片上传 `422 part_mismatch` | 客户端提交的分片摘要与服务端暂存不符 | 重新上传该分片；`GET /api/v1/buckets/{bucket}/uploads/{id}` 可查看服务端分片 |

更多细节见[技术手册](/manual)：权限模型、错误码全表、数据模型与 GC 语义。
