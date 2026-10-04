# SRP-6a 本地口令认证与密钥协商服务

基于标准 **SRP-6a**（RFC 2945 / RFC 5054）的双向认证与会话密钥协商 HTTP 服务。
服务端在任何环节都不接收或保存口令明文，只保存由口令派生的验证器 `v = g^x`。

## 1. 协议流程

默认参数：

- 群：RFC 5054 2048 位安全素数群（`g = 2`）。
- 哈希：`SHA-256`。
- 乘法常量：`k = SHA-256(N | g)`，由群参数导出。
- `x` 派生：`PBKDF2-HMAC-SHA-256(identity, salt, password, iterations)`，
  迭代次数可配置（默认 100000），用于抵抗离线字典攻击。
- 所有大整数在哈希前以群宽定长字节（256 字节）编码。

### 1.1 注册（口令不出客户端）

客户端本地：

1. 生成随机盐 `s`。
2. `x = PBKDF2(...)`，`v = g^x mod N`。
3. 仅上送 `identity, salt, v`（以及可选的参数标识）。

服务端把记录写入临时文件后 `ATOMIC_MOVE` 落盘，崩溃不会出现半写入记录。

### 1.2 双向认证

1. 客户端生成私钥 `a`，公钥 `A = g^a`，请求 `/challenge`。
2. 服务端生成私钥 `b`，公钥 `B = k*v + g^b mod N`，返回盐、`B` 和握手 ID。
   握手状态钉住发起时刻的验证器版本（version snapshot）。
3. 双方独立计算：
   - `u = SHA-256(PAD(A) | PAD(B))`
   - 客户端 `S = (B - k*g^x)^(a + u*x) mod N`
   - 服务端 `S = (A * v^u)^b mod N`
   - 会话密钥 `K = SHA-256(PAD(S))`
4. 客户端证明 `M1 = SHA(H(N)^H(g) | H(I) | s | A | B | K)` 上送 `/verify`。
5. 服务端以恒定时间比较 M1，失败则整体拒绝；成功后返回
   `M2 = SHA(A | M1 | K)` 供客户端验证服务端。
6. 双方得到一致的会话密钥，服务端同时签发有期限会话令牌。

任一证明不匹配都会删除握手状态并计入失败次数，不允许“部分成功”，
客户端对 M2 的验证保证两端结论一致。

### 1.3 验证器轮换（改口令）

- `/rotate` 必须携带有效会话令牌，即口令修改只能基于已完成的认证会话。
- 轮换以原子文件替换完成，版本号自增。
- 进行中的握手持有旧验证器快照：在轮换开始后完成，仍按旧验证器成功；
  轮换之后发起的新握手使用新验证器，旧口令无法通过证明，结果确定、无状态偏斜。

## 2. HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/srp/params` | 返回协议、群、哈希、派生方式与迭代次数 |
| POST | `/api/srp/register` | 注册 identity + salt + verifier |
| POST | `/api/srp/challenge` | 提交 A，返回握手 ID、salt、B |
| POST | `/api/srp/verify` | 提交 M1，返回 M2 与会话令牌 |
| POST | `/api/srp/rotate` | 携带 `Authorization: Bearer <token>` 轮换验证器 |
| POST | `/api/srp/logout` | 吊销当前令牌 |
| GET | `/api/srp/protected` | 受保护资源，需 Bearer 令牌 |
| GET | `/api/admin/audit?type=&identity=&limit=` | 查询审计记录 |
| POST | `/api/admin/policy` | 更新迭代次数 / 锁定阈值 / 锁定时长 |
| POST | `/api/admin/unlock` | 手动解锁 |

所有数值使用小写十六进制；`A/B/salt/verifier` 使用定长十六进制。

## 3. 错误码（可区分，不含口令信息）

`INVALID_FORMAT`、`INVALID_PUBLIC_KEY`（含零公钥、越界）、`UNKNOWN_IDENTITY`、
`PROOF_MISMATCH`、`REPLAY_DETECTED`、`SESSION_NOT_FOUND`、`SESSION_EXPIRED`、
`ACCOUNT_LOCKED`、`UNAUTHORIZED`、`IDENTITY_TAKEN`、`POLICY_VIOLATION`。

说明：

- 证明比较使用 `MessageDigest.isEqual`（JDK 恒定时间原语）。
- 未知身份执行等价开销的 SRP 诱饵运算后返回 `UNKNOWN_IDENTITY`，
  响应结构与其他失败一致，避免响应时间/结构成为用户枚举侧信道。
- 协议违规的错误信息不包含盐、验证器或任何口令派生数据。

## 4. 防重放、锁定与会话

- 同一客户端临时公钥 `A` 的重复使用在可配置保留期内被识别为重放并拒绝，
  重放集合持久化，重启后仍然有效。
- 失败计数按 **身份 × 来源地址** 维度独立累计；达到阈值返回 `423 Locked`，
  到达锁定时长后自动解锁，也可通过管理接口解锁。
- 会话令牌为 256 位随机值，有 TTL，可吊销；令牌持久化，崩溃后仍有效直到过期。

## 5. 持久化与崩溃恢复

数据目录由 `srp.data-dir` 配置，默认 `./data`：

- `verifiers/<sha256(identity)>.json`：身份与验证器，原子写入。
- `audit.jsonl`：仅追加 JSON Lines 审计日志。
- `replay.json`：已用临时公钥及过期时间。
- `sessions.json`：有效会话令牌。
- `locks.json`：失败计数与锁定截止时间。
- `policy.json`：运行期策略覆盖，重启后恢复。

文件名使用身份的 SHA-256，避免身份中的特殊字符造成路径问题。

## 6. 配置项（`application.properties`）

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `srp.data-dir` | `data` | 持久化目录 |
| `srp.digest` | `SHA-256` | 哈希算法 |
| `srp.derivation` | `PBKDF2` | x 派生方式（`PBKDF2` 或 `RFC2945`） |
| `srp.iterations` | `100000` | PBKDF2 迭代次数 |
| `srp.salt-bytes` | `16` | 盐长度（字节） |
| `srp.max-failures` | `5` | 触发锁定的失败次数 |
| `srp.lock-seconds` | `900` | 锁定时长（秒） |
| `srp.handshake-ttl-seconds` | `120` | 握手有效期 |
| `srp.session-ttl-seconds` | `3600` | 会话令牌有效期 |
| `srp.replay-retention-seconds` | `86400` | 临时公钥重放保留期 |

通过 `/api/admin/policy` 修改的迭代次数与锁定策略会写入 `policy.json`，重启后保持。

## 7. 安全假设与边界

- 服务端代码与运行环境可信；HTTPS/传输层安全由部署方提供（本服务不在 HTTP 层做 TLS）。
- 客户端必须独立验证 M2，且口令只在客户端本地参与运算。
- PBKDF2 提高离线猜测成本，但无法替代强口令；高安全场景可调高迭代次数。
- 互操作要求对端使用相同群、哈希、`k/u/M1/M2` 编码与 x 派生方式；
  `RFC2945` 派生 + `SHA-1` 仅用于标准向量兼容，不用于生产。

## 8. 构建与测试

```bash
mvn test
```

测试覆盖：

- RFC 5054 附录 B 公开标准测试向量（x、v、k、A、B、u、S、K）。
- 零/越界公钥、非法格式等参数异常与可区分错误码。
- 临时公钥重放拒绝。
- 轮换与进行中握手并发时的版本快照确定性、并发轮换、未认证轮换拒绝。
- 失败计数、锁定、按身份/来源隔离、解锁。
- 注册、轮换、锁定、审计、会话在进程“重启”后的保持。

参考客户端见 `src/main/java/.../client/SrpClient.java`，
可用于生成注册材料与演示完整握手。
