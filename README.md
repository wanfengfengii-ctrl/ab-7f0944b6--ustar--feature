# TAR Bundle Attestation Service

科研设备供应商提交 TAR 配置包时，隔离环境在导入前通过本服务确认**文件集合唯一、
摘要明确**：严格只接受未压缩的 POSIX.1 USTAR 普通文件包，杜绝路径别名、重复条目、
损坏尾块等让同一字节流产生不同解释的情况。

仅依赖 Python 3.11 标准库；测试使用 pytest。

## 运行

```bash
# 直接运行
python -m app.server                     # 默认 0.0.0.0:8080
PORT=9000 python -m app.server

# Docker
docker compose up --build                # 宿主机端口默认 8080
TAR_PORT=9000 docker compose up --build  # 自定义宿主机端口

# 一次性校验（编译 + 全部代码测试 + 三类冒烟），以退出码报告结果
docker compose run --rm verify           # 0 通过 / 1 失败
```

健康检查：

```bash
curl -s http://localhost:8080/health
# {"status": "ok"}
```

## 接口

### `POST /api/bundles/attest`

- 请求：`Content-Type: application/x-tar`（允许附带 `; charset=...` 参数），
  必须带 `Content-Length`；拒绝压缩（`Content-Encoding: gzip` 等）与
  `Transfer-Encoding: chunked`。
- 可选请求头 `X-Bundle-Manifest-Sha256`：供应商发布系统预登记的包内声明文件
  `BUNDLE.MANIFEST` 原始字节 SHA-256（**小写**十六进制，64 字符）。省略时
  既有契约完全不变；提供时进入声明核验流程（见下）。
- 请求体：未压缩 USTAR，**整体不超过 8 MiB**。

成功 `200`：

```json
{
  "bundleSha256": "…",
  "entries": [
    {"path": "dir/a.bin", "size": 123, "sha256": "<内容摘要>"},
    {"path": "readme.txt", "size": 10, "sha256": "<内容摘要>"}
  ],
  "manifestSha256": "…"
}
```

- `entries` 按路径的 **UTF-8 字节序**排序。
- 每条给出 `path`、`size`、文件内容的 `sha256`（小写十六进制）。
- 仅当请求携带 `X-Bundle-Manifest-Sha256` 且声明核验通过时，结果才包含
  `manifestSha256`（等于声明文件原始字节摘要，也等于请求头值）。
- `bundleSha256` 计算方式（全部大端、按排序后顺序）：
  依次拼接每项的四字节路径长度（`>I`）、路径 UTF-8 字节、八字节大小（`>Q`）、
  32 字节原始 SHA-256 摘要，对拼接结果整体取 SHA-256。

### 声明文件核验（`X-Bundle-Manifest-Sha256`）

提供请求头时，包内**必须恰有一个**名为 `BUNDLE.MANIFEST` 的普通文件成员，
且服务按下列顺序核验，任一失败即返回错误，**绝不返回部分清单**：

1. 先对 `BUNDLE.MANIFEST` 的**原始字节**取 SHA-256，与请求头逐字符比较，
   不符返回 `manifest_digest_mismatch`（409）；
2. 解析声明文本，逐项比对包内其余成员的路径、大小与内容摘要，存在缺项、
   多项或任一属性不符返回 `manifest_conflict`（409）。

声明文件格式：

- ASCII 文本；每行为 `<sha256>\t<size>\t<path>`，两个制表符分隔三字段；
  `sha256` 为 64 位小写十六进制，`size` 为规范十进制（`0` 或非零开头数字）；
- 每行（含最后一行）以单个 LF 结束，不允许空行、CRLF 或行尾杂字节；
- 路径按 UTF-8 字节序**严格递增**，为合法相对路径（与包内路径同一套规则），
  且不得列出 `BUNDLE.MANIFEST` 自身；
- 声明必须**恰好覆盖除声明文件外的全部成员**：漏装（声明有、包内无）、
  整组替换/夹带（包内有、声明无）或大小/内容摘要不符，一律拒绝。

格式错误返回 `bad_manifest`（422），错误体含 1-based `line`：

```json
{"error": {"category": "bad_manifest", "message": "…", "line": 3}}
```

失败响应一律不返回任何部分清单：

```json
{"error": {"category": "bad_checksum", "message": "…", "entry": 1}}
```

`entry`（存在时）为包内成员的 1-based 序号，可直接定位问题条目。

## 接受条件（全部满足）

- 1 至 100 个成员，且全部是普通文件（typeflag `0`，兼容历史值 `\0`）；
- 文件内容合计不超过 6 MiB；
- 头块 magic 为 `ustar\0`、version 为 `00`；校验和必须与头块一致；
- 所有标准数值字段（mode/uid/gid/size/mtime/devmajor/devminor）为合法八进制；
  普通文件头的设备号必须为 0、不得携带 linkname；
- 每个成员的数据块完整、填充字节必须全为零；
- 结束标记为连续两个 512 字节全零块；其后只允许全零的记录填充
  （兼容 GNU tar 默认 10240 字节记录边界），任何非零尾块一律拒绝；
- 路径为合法 UTF-8 且已做 **NFC** 规范化的相对路径，仅以 `/` 分段；
  禁止：空段、`.`/`..` 点段、反斜杠、控制字符、绝对路径；
- USTAR `prefix` 与 `name` 拼接后整体校验；重复路径（含不同切分方式拼成
  同一路径，如 `prefix=d, name=f` 与 `name=d/f`）一律拒绝；
- 链接、目录、设备、PAX/GNU 扩展头、长名头等非 USTAR 普通文件类型全部拒绝。

## 错误类别

| category             | 含义 |
| --- | --- |
| `empty_archive`      | 空请求或只有结束块，成员数为 0 |
| `payload_too_large`  | 归档整体超过 8 MiB（或声明的 Content-Length 超限） |
| `content_too_large`  | 文件内容合计超过 6 MiB |
| `too_many_entries`   | 成员超过 100 个 |
| `truncated`          | 长度非 512 整数倍、头/数据块截断 |
| `bad_checksum`       | 头块校验和不匹配或非八进制 |
| `non_ustar`          | magic/version 不是 `ustar\0`/`00` |
| `unsupported_type`   | 非普通文件类型（链接、目录、PAX/GNU 扩展头等） |
| `malformed_header`   | 字段非八进制、尾部有杂字节、非法设备号或携带 linkname |
| `bad_padding`        | 数据填充区出现非零字节 |
| `bad_terminator`     | 缺少结束标记或第二结束块非零 |
| `trailing_data`      | 结束标记之后存在非零数据 |
| `invalid_path`       | 非 UTF-8、非 NFC、绝对路径、点段、反斜杠、控制字符、空段 |
| `bad_manifest`       | 声明文件格式错误（非 ASCII/LF、字段数错、摘要小写 hex/大小规范十进制词法错、路径非法或未严格递增），带 `line` |
| `manifest_digest_mismatch` | `BUNDLE.MANIFEST` 原始字节摘要与预登记请求头不符 |
| `manifest_conflict`  | 声明覆盖与实际成员集合不一致（缺项、多项）或路径/大小/内容摘要逐项不符 |
| `duplicate_path`     | 路径重复（含 prefix 拼接歧义） |
| `unsupported_media_type` | Content-Type/Content-Encoding 不符 |
| `bad_request` / `length_required` / `truncated`（传输层） | 请求分帧问题 |

## 测试

```bash
pip install pytest
python -m pytest -q        # 100 个用例
python scripts/verify.py   # 与 Compose verify 服务相同的一次性校验
```

测试用逐字节构造的归档覆盖：坏校验和、非零填充、单零块/脏第二零块、
尾部非零数据、截断、点段/绝对路径/反斜杠/控制字符/NFD/非法 UTF-8、
prefix 切分冲突、PAX/GNU 拒绝、GNU tar（`--format=ustar`）互操作，
以及声明核验的兼容请求、有效声明、预登记摘要不符、逐项内容摘要不符和
清单漏项等场景。
