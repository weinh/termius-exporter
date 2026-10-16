# 变更日志 / Changelog

## [Unreleased] - 2026-10-16

### 重写数据读取层

旧版 `extractAndDecrypt()` 把所有 `.log`/`.ldb` 文件按原始字节拼接，正则匹配 `BA[base64]` 找加密块。存在两个问题：

1. **残留已删除记录**：LevelDB 是 append-only，删除以无密文的 tombstone 条目表示；正则重新纳入旧密文、又忽略 tombstone，导致已删除记录重现。
2. **漏读 SSTable 记录**：`.ldb` 数据块是 Snappy 压缩的，密文非明文 ASCII，正则无法匹配；且旧分类器 `host && user_name && connection_type` 匹配不到真正的主机定义（store16 用 `address`/`label`/`ssh_config`），只匹配到会话记录（store32）。

### 新增 / Added
- **`leveldb-read.js`**：自包含 LevelDB 读取器（不依赖 leveldown/level，因 Chromium 用自定义 `idb_cmp1` 比较器无法打开）。
  - 解析 `.log` WAL：32KB 块记录 → WriteBatch put/delete，遵循删除 tombstone。leveldb ValueType：1=Value(Put)、0=Deletion。
  - 解析 `.ldb` SSTable：footer → index block → Snappy 解压后的数据块，共享键前缀解码。
  - footer 定位不依赖 magic：Chromium 的 SSTable magic 与上游不同（`57fb808b247547db`，非上游 `21ea8f92247f47db`），改用结构不变量 `index.offset + size + 5(trailer) === footerStart` 校验。
  - 内置纯 JS Snappy 原始格式解码器（无新依赖）。
  - `readCurrentValues()`：以 SSTable 为基、WAL 叠加并应用删除 → 当前 key→value map。
  - `decodeIdbKeyPrefix()`：解析 IndexedDB 键前缀 `[db][store][index]` varints。
  - `deserializeValue()`：用 `v8.deserialize`（偏移 5）解码 Blink SSV 包装的 V8 结构化克隆（实体即以此形式存储）。

### 变更 / Changed
- **`termius-exporter.js`**：重写数据层（保留 `getEncryptionKey`、密钥链、CSV/PEM 输出格式不变，importer 仍可用）。
  - `buildModel()`：遍历当前记录反序列化 V8 实体；解密每个实体的 `content` 同步载荷并合并为权威字段；加载「加密 blob 实体」并从 LevelDB 键恢复 `local_id`。
  - `buildHostRows()`：关系连接 host(store16) → ssh_config(store4 / store9，store9 再嵌套一层 ssh_config→store4 取 port、identity→store12) → identity 的 username/password + ssh_key(store11)；按 `local_id` 去重（不再按 `host:port` 合并而丢主机）。
  - 过滤软删除：跳过 `status` 匹配 `/delete/i` 的记录（`DELETE_FAILED` 等，记录残留但 UI 隐藏）。
  - `decryptField()`：解密实体内的加密子字段（password / private_key / passphrase / username）。
  - `exportSshKeys()` / `exportSnippets()`：改为从 store11 / store13 读取，并过滤软删除。
  - 新增 `--debug` 诊断（仅计数，不含敏感值）：footer/数据块/键分布、每 store 实体计数、join 覆盖率。

### 局限 / Known limitations
- 凭据覆盖依赖关系连接 host→ssh_config→identity。已处理：重复记录按完整度去重、`content` 同步载荷只合并非凭据字段（避免 stale sync 把账号密码错位覆盖）、`local_id` 缺失时从 LevelDB 键恢复（`01 03 [8-byte double LE]`，仅对非 config store 补齐以免 store4/store9 共享 local_id 空间误匹配）。仍可能：某主机引用的 identity 已从 DB 删除、或主机无 `ssh_config`（telnet/cloud），则该行凭据为空——此为本地数据状态，非读取逻辑缺陷。

### 未改动 / Unchanged
- `termius-importer.js`、`HOW_TO_IMPORT.md`、`README.md`、`package.json`（无新依赖，Snappy 内置，libsodium/keytar 已存在）。
