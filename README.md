# WebDAV to S3 Gateway

一个多租户 Node.js 网关，对外暴露 S3 兼容接口，对内把对象正文写入 WebDAV 上游。S3 元数据可以继续写入 WebDAV 隐藏状态目录，也可以切换到 SQLite 元数据索引。

目标是让 AWS SDK、AWS CLI、浏览器 Presigned URL 和常见 S3 客户端可以把它当作本地 S3 endpoint 使用。当前实现覆盖了核心数据面、常见控制面和本地仿真语义，但不等同于完整 AWS S3 云服务。

## 当前能力

### 访问与鉴权
- SigV4 Header 签名
- SigV4 Presigned URL
- Session Token 本地校验
- 浏览器 POST policy 上传
- SigV4 streaming/chunked payload 标识与 AWS chunked 正文还原
- path-style endpoint，例如 `http://127.0.0.1:9000/demo-bucket/path/to/file.txt`
- virtual-host-style bucket 解析

### 对象数据面
- `PutObject`
- `GetObject`
- `HeadObject`
- `DeleteObject`
- `CopyObject`
- 条件请求：`If-Match`、`If-None-Match`、`If-Modified-Since`、`If-Unmodified-Since`
- response header override，例如 `response-content-type`
- user metadata：`x-amz-meta-*`
- object tagging：`GET/PUT/DELETE ?tagging`
- checksum / `Content-MD5` 基础校验
- versionId、delete marker、指定版本读取和删除
- object legal hold / retention 的本地阻止覆盖与删除语义

### Multipart Upload
- `CreateMultipartUpload`
- `UploadPart`
- `ListParts`
- `CompleteMultipartUpload`
- `AbortMultipartUpload`
- `ListMultipartUploads`

Multipart part 会先写入 WebDAV 隐藏 staging 路径，complete 时由网关读取 parts 并合并为最终对象。SQLite metadata 模式下，最终对象正文会进入 content-addressed blob 根目录，完成或中止后会清理临时 part blob。WebDAV 上游没有 S3 原生 compose 能力，因此 complete 成本高于 AWS S3。

### 桶与控制面
- `ListBuckets`
- `HeadBucket`
- `CreateBucket` 兼容响应
- `DeleteBucket` 受配置桶约束，默认返回不可删除语义
- `GetBucketLocation`
- `ListObjectsV2`
- `ListObjectVersions`
- bucket ACL 兼容响应
- bucket policy / cors / tagging / lifecycle / encryption / public access block 的本地配置态读写
- bucket versioning：`Off` / `Enabled` / `Suspended`

### 生命周期
- 后台单次或周期扫描
- 非当前版本过期清理
- delete marker 过期清理
- multipart 清理能力的状态基础
- SQLite 元数据模式下可显式开启未引用 content-addressed blob GC，默认关闭

### 观测与健康检查
- `GET /healthz`
- `GET /readyz`
- 请求日志与 `x-amz-request-id`

## S3 兼容矩阵

| 范围 | 状态 | 说明 |
|---|---:|---|
| AWS SDK path-style 常用对象命令 | 已覆盖 | `PutObject` / `HeadObject` / `GetObject` / `ListObjectsV2` / `DeleteObject` 有真实本地 endpoint 回归 |
| AWS SDK multipart | 已覆盖 | `CreateMultipartUpload` / `UploadPart` / `CompleteMultipartUpload` / 最终 `GetObject` 有回归 |
| Presigned URL | 已覆盖 | 浏览器式 `GET` 和真实 endpoint `PUT/GET` 已覆盖 |
| POST policy | 已覆盖 | 浏览器 form-data 上传已覆盖 |
| virtual-host-style | 已覆盖 | bucket 级与对象级请求已覆盖 |
| AWS CLI `s3 cp/ls/rm` | 条件覆盖 | 测试环境存在 `aws` 命令时自动执行；当前开发环境没有 CLI 时会跳过 |
| Bucket policy / cors / acl / encryption / public access block | 本地配置态 | 提供兼容读写或响应，不连接 AWS 外部服务 |
| Versioning / lifecycle / object lock | 本地仿真 | 元数据和阻止删除/覆盖语义在本地实现 |
| SQLite metadata backend | 可选增强 | 默认不启用；启用后对象索引、版本、multipart、控制面状态由 SQLite 承担，WebDAV 只作为 blob 存储 |
| IAM / KMS / 通知 / 复制 / CloudTrail | 未实现 | 属于 AWS 云服务集成，不在本地 WebDAV 网关内真实执行 |

## 存储模式与状态目录

网关支持两种 metadata backend。默认模式仍然不依赖 SQLite。

### WebDAV metadata 模式

这是默认模式，也是旧行为兼容模式。对象正文写入每个 bucket 配置的 `rootPath`，S3 元数据、控制面状态、multipart 会话和版本索引写入 WebDAV 隐藏目录：

```text
/.webdavtos3-system
```

主要结构：

```text
/.webdavtos3-system/buckets/<bucket>/bucket.json
/.webdavtos3-system/buckets/<bucket>/objects/<key-hash>.json
/.webdavtos3-system/buckets/<bucket>/multipart/<upload-id>/upload.json
/.webdavtos3-system/buckets/<bucket>/multipart/<upload-id>/parts/<part-number>
/.webdavtos3-system/buckets/<bucket>/versions/index.json
/.webdavtos3-system/buckets/<bucket>/versions/data/<version-id>/<key-hash>
```

该模式保留原有对外 S3 行为，但对象列表和状态恢复仍依赖 WebDAV 文件结构与 `PROPFIND` 能力；不提供 SQLite 模式的全局对象索引、content-addressed blob 引用追踪和安全 blob GC。

### SQLite metadata 模式

启用 SQLite 后，bucket 状态、对象元数据、当前对象索引、对象版本、multipart 状态和控制面配置由 SQLite 文件保存。WebDAV 上游只承担 blob 存储。

新写入对象正文会保存到 content-addressed blob 根目录：

```text
/.webdavtos3-blobs
```

典型路径：

```text
/.webdavtos3-blobs/sha256/<first-2>/<next-2>/<sha256>
```

SQLite 模式下，`ListObjectsV2` 走 SQLite 对象索引，不再依赖 WebDAV `PROPFIND` 枚举对象正文路径。删除对象或版本会先更新元数据引用；物理 blob 清理需要显式开启 lifecycle GC，并且只会扫描 `/.webdavtos3-blobs` 下未被 SQLite metadata 引用的 blob。

注意：不要把 `/.webdavtos3-system` 或 `/.webdavtos3-blobs` 暴露给普通 WebDAV 用户编辑。删除或篡改这些目录会导致 S3 metadata、版本、tagging、multipart 会话、控制面配置或对象正文引用丢失。

## 配置

默认从环境变量 `WEBDAVTOS3_CONFIG` 指定的 JSON 文件加载。
未指定时，默认读取当前工作目录下的 `webdavtos3.config.json`。

可以从 `webdavtos3.config.example.json` 复制一份开始。

### 配置结构

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 9000,
    "trustProxy": true,
    "maxObjectSizeBytes": 5368709120,
    "requestTimeoutMs": 300000
  },
  "s3": {
    "region": "us-east-1"
  },
  "metadata": {
    "driver": "webdav"
  },
  "lifecycle": {
    "enabled": false,
    "intervalMs": 3600000,
    "expireNoncurrentVersionsAfterMs": 604800000,
    "expireDeleteMarkersAfterMs": 604800000,
    "gcUnreferencedBlobs": false
  },
  "tenants": [
    {
      "id": "tenant-a",
      "accessKeyId": "demo-access-key",
      "secretAccessKey": "demo-secret-key",
      "sessionToken": "optional-session-token",
      "upstreams": [
        {
          "id": "primary",
          "endpoint": "https://dav.example.com/remote.php/dav/files/demo",
          "username": "demo-user",
          "password": "demo-password",
          "rejectUnauthorized": true,
          "connectTimeoutMs": 10000,
          "requestTimeoutMs": 120000
        }
      ],
      "buckets": [
        {
          "name": "demo-bucket",
          "upstreamId": "primary",
          "rootPath": "/s3-root",
          "region": "us-east-1"
        }
      ]
    }
  ]
}
```

`metadata.driver` 可选值：

| 值 | 行为 |
|---|---|
| `webdav` | 默认值。不使用 SQLite，保留旧 WebDAV 隐藏状态目录和对象路径行为。 |
| `sqlite` | 使用 SQLite 保存 S3 metadata/index/control state；WebDAV 只保存 blob 正文。需要提供 `metadata.path`。 |

SQLite 示例：

```json
{
  "metadata": {
    "driver": "sqlite",
    "path": "./data/webdavtos3.sqlite"
  },
  "lifecycle": {
    "enabled": false,
    "intervalMs": 3600000,
    "gcUnreferencedBlobs": false
  }
}
```

`gcUnreferencedBlobs` 只对 SQLite metadata 模式有意义，并且默认关闭。开启后，lifecycle 会根据 SQLite 中仍被 current object、object version 或 multipart upload 引用的 `bodyPath` 判断是否可以删除 `/.webdavtos3-blobs` 下的物理 blob。

## 本地运行

```bash
npm install
copy webdavtos3.config.example.json webdavtos3.config.json
npm run dev
```

## 构建

```bash
npm run build
npm start
```

## 用 AWS CLI 指向本服务

```bash
aws --endpoint-url http://127.0.0.1:9000 s3 ls
aws --endpoint-url http://127.0.0.1:9000 s3 cp ./local.txt s3://demo-bucket/path/local.txt
aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://demo-bucket/path/
aws --endpoint-url http://127.0.0.1:9000 s3 rm s3://demo-bucket/path/local.txt
```

如果从其他机器访问，不要使用 `127.0.0.1` 作为外部 endpoint。请把客户端 endpoint 配成该机器可访问的域名或 IP。

## 常用客户端环境变量

```bash
S3_ENDPOINT_INTERNAL=http://127.0.0.1:9000
S3_ENDPOINT_EXTERNAL=http://127.0.0.1:9000
S3_REGION=us-east-1
S3_BUCKET=demo-bucket
S3_ACCESS_KEY=demo-access-key
S3_SECRET_KEY=demo-secret-key
S3_FORCE_PATH_STYLE=true
```

## 模块边界

- `src/http`：HTTP 入口、内容类型适配、健康检查
- `src/s3`：S3 协议解析、鉴权、路由、XML 响应、错误模型、metadata/blob 后端与生命周期
- `src/tenancy`：租户、access key 与 bucket 路由
- `src/webdav`：WebDAV 请求、路径映射、对象与列表适配
- `src/config`：配置加载与校验
- `src/observability`：请求日志与请求标识

## 与 AWS S3 的主要差异

- WebDAV 不提供 S3 原生事务、compose、对象锁、IAM、KMS、事件通知或跨区域复制能力；相关能力只能做本地状态或本地阻止语义。
- Multipart complete 需要网关读取所有 part 并写入最终对象，性能取决于 WebDAV 上游和网关带宽。
- bucket 是配置绑定，不是 AWS 账户级资源；`CreateBucket` / `DeleteBucket` 只提供兼容响应或受限语义。
- `ETag`、`Last-Modified`、列表时间等会尽量规范化为 S3 客户端可解析格式，但底层仍受 WebDAV 上游行为影响。
- WebDAV metadata 模式下，状态目录不是 AWS 管理面数据库，备份和迁移时需要同时保留对象正文目录与 `/.webdavtos3-system`。
- SQLite metadata 模式下，备份和迁移需要同时保留 SQLite 文件与 WebDAV 上的 `/.webdavtos3-blobs`。
