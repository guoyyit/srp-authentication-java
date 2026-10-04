# SRP-6a 本地口令认证与密钥协商服务

基于 Spring Boot 3 / Java 17 实现的标准 **SRP-6a**（RFC 2945 / RFC 5054）口令认证与密钥协商（PAKE）HTTP 服务。
服务端在**任何环节都不接收、不存储口令明文**：注册时只保存身份名、盐与由口令派生的验证器（verifier `v = g^x mod N`），
口令泄露面仅存在于客户端。即使验证器库整体泄露，攻击者也只能对高熵拉伸后的验证器做离线猜测，且会受到 PBKDF2 迭代成本的约束。

## 协议流程

```
客户端                                            服务端
  |  注册（一次性，离线或带外完成）                 |
  |  x = PBKDF2(H(I:P), salt, iterations)         |
  |  v = g^x mod N                                 |
  |  ---- POST /api/srp/register {I,salt,v} ---->  | 原子落盘 (I,salt,v,digest,iters)
  |                                                |
  |  登录阶段 1：交换临时公钥                        |
  |  a 随机; A = g^a mod N                         |
  |  ---- POST /api/srp/handshake {I,A} -------->  | 校验 A、锁定、重放
  |                                                | 快照 (salt,v)
  |                                                | b 随机; B = k*v + g^b mod N
  |  <--- {sessionId, salt, B, digest,iters} ----- |
  |                                                |
  |  u = H(PAD(A)|PAD(B));  k = H(N|PAD(g))       | u,k 双方各自独立计算
  |  S_c = (B - k*g^x)^(a+u*x) mod N              | S_s = (A * v^u)^b mod N
  |  K = H(S)                                      | K = H(S)
  |  M1 = H( H(N)^H(g) | H(I) | s | A | B | K )   |
  |  ---- POST /api/srp/verify {sessionId,M1} -->  | 恒定时间比较 M1
  |                                                | M2 = H(A | M1 | K)
  |  <--- {M2, token, expiresAt} ----------------- | 签发会话令牌
  |  恒定时间校验 M2                                |
  |                                                |
  |  ---- GET /api/protected/ping (Bearer token)>  |
```

- 默认群：**RFC 5054 Appendix A 的标准 2048 位质数群**，生成元 g=2；乘法常量 `k = H(N | PAD(g))` 由群参数导出。
- 默认哈希 SHA-256；口令拉伸为 `x = PBKDF2-HMAC-SHA256(H(I:":"P), salt, iterations)`，迭代次数可配置（默认 20000）。
- 会话密钥 `K = H(S)`，仅在客户端/服务端内存中生成，永不出网、不落盘。
- 两段证明 M1/M2 构成双向认证；任一证明不匹配即整体拒绝，不存在“半认证”状态。

## HTTP 接口

所有二进制字段（salt、M1、M2）使用标准 Base64；大整数（verifier、A、B）以十进制 JSON 数字传输。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/srp/register` | 注册 `{identity, salt, verifier, digestAlgorithm?, iterations?}`，原子落盘 |
| POST | `/api/srp/handshake` | `{identity, a}` → `{sessionId, salt, b, digestAlgorithm, iterations}` |
| POST | `/api/srp/verify` | `{sessionId, m1}` → `{m2, token, expiresAt, identity}` |
| POST | `/api/srp/change-password` | 持已认证 token 轮换 `{token, salt, verifier, ...}` |
| POST | `/api/srp/logout` | `{token}` 吊销会话 |
| GET  | `/api/srp/protected/ping` | Bearer 令牌保护的示例资源 |
| GET  | `/api/srp/audit?identity=&eventType=&limit=` | 查询审计记录（新到旧） |
| POST | `/api/srp/admin/unlock` | `{identity}` 管理员手动解锁 |

### 可区分错误码

`MALFORMED_MESSAGE`(400)、`INVALID_IDENTITY`(400)、`INVALID_SALT`(400)、`INVALID_VERIFIER`(400)、
`INVALID_PUBLIC_KEY`(400，A 为零/越界)、`INVALID_PROOF`(401)、`INVALID_SESSION`(401/404)、
`SESSION_EXPIRED`(410)、`SESSION_COMPLETED`(409)、`REPLAY_DETECTED`(409)、
`VERIFIER_ROTATED`(409)、`ACCOUNT_LOCKED`(423)、`IDENTITY_EXISTS`(409)。

## 安全设计与假设

- **服务器零口令知识**：注册/修改只接收 salt 与 verifier；协议错误信息不含任何口令材料。
- **防账户枚举**：未知身份在握手阶段返回由身份确定性生成的诱饵记录（同样的 PBKDF2 成本、字段形状），
  在证明阶段返回与口令错误完全一致的 `INVALID_PROOF`。
- **输入收紧**：A/B/verifier 必须满足 `1 <= value < N`，零、负值、越界立即拒绝；u 为零由客户端拒绝；
  salt 长度 8–256 字节；JSON 非法返回 `MALFORMED_MESSAGE`。
- **恒定时间比较**：证明比对使用 `MessageDigest.isEqual`。
- **防重放**：每个 `(identity, A)` 的哈希被持久化，同一临时公钥再次出现即拒绝（`REPLAY_DETECTED`）。
- **并发轮换确定性**：握手开始时对 `(salt, verifier)` 做快照；轮换口令后，所有按旧验证器发起的在途握手
  在 verify 时被明确拒绝（`VERIFIER_ROTATED`），新握手按新验证器完成。结果只有两种：按快照成功，或被拒绝。
- **防猜测**：失败计数同时按“身份”与“身份+来源地址（支持 X-Forwarded-For 首段）”累计；
  达到阈值后在锁定期内拒绝，窗口过期自动解锁，也可管理员解锁。
- **持久化与崩溃恢复**：注册/轮换/锁定/会话/重放表均以“临时文件 + fsync + 原子 rename”落盘；
  审计日志为 fsync 顺序追加，启动时逐行回放，崩溃产生的残缺末行自动跳过。
- **假设与边界**：传输层应部署在 HTTPS 之后（本服务不自行提供通道加密）；
  `/api/srp/audit` 与 `/admin/unlock` 为管理面，生产部署应在网关层加访问控制；
  会话令牌为不透明随机串，吊销立即生效。

## 配置项（`src/main/resources/application.properties`，重启后保持）

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `srp.data-dir` | `data` | 持久化状态目录 |
| `srp.digest-algorithm` | `SHA-256` | 新注册默认摘要（每条注册独立记录） |
| `srp.iterations` | `20000` | PBKDF2 迭代次数，越大越抗离线字典攻击 |
| `srp.handshake-ttl-seconds` | `120` | 握手会话有效期 |
| `srp.session-ttl-seconds` | `3600` | 会话令牌有效期 |
| `srp.max-failures` | `5` | 锁定阈值（身份维度与来源维度各自计数） |
| `srp.lock-seconds` | `900` | 锁定时长 |

## 标准互操作验证

`crypto/Rfc5054TestVectorsTest` 逐条核对 RFC 5054 Appendix B 公开测试向量（1024 群 + SHA-1 + 经典拉伸）：
`k / x / v / A / B / u / S`（客户端与服务端两侧）以及 M1/M2 一致性，共 8 项断言。
默认 2048 群下另有完整的端到端互操作测试（客户端参考实现 ↔ HTTP 服务端，双端会话密钥与证明一致）。

## 测试覆盖

- 标准测试向量：`Rfc5054TestVectorsTest`
- 参数异常与恒定时间：`SrpCryptoGuardsTest`（零/负/越界公钥、长度差异、非法迭代数）
- 端到端双向认证、保护接口、吊销、错误口令、非法 JSON、未知身份不可枚举、审计查询：`SrpEndToEndIntegrationTest`
- 重放：`ReplayDetectionIntegrationTest`
- 失败锁定/解锁与来源隔离：`LockoutIntegrationTest`
- 并发轮换：`ConcurrentRotationIntegrationTest`
- 崩溃恢复（注册/轮换/锁定/审计/令牌）：`CrashRecoveryIntegrationTest`

## 运行

```bash
mvn spring-boot:run        # 启动 HTTP 服务，默认 8080
mvn test                   # 运行全部测试
```

客户端侧需自行按同样公式生成 `x/v`（注册）与 `A/M1`（登录）；测试目录中的 `SrpTestClient`/`SrpClient`
可作为无依赖的参考实现。
