# WebDAV to S3 Gateway

一个多租户 Node.js 网关，对外暴露 S3 风格接口，对内转发到 WebDAV 上游。

## 当前能力
- 多租户：`accessKeyId -> tenant -> bucket -> WebDAV rootPath`
- S3 SigV4 Header 鉴权
- path-style endpoint，例如 `http://127.0.0.1:9000/demo-bucket/path/to/file.txt`
- 基础对象操作
  - `PutObject`
  - `GetObject`
  - `HeadObject`
  - `DeleteObject`
  - `CopyObject`
- 桶与列表视图
  - `ListBuckets`
  - `HeadBucket`
  - `ListObjectsV2`
- 健康检查
  - `GET /healthz`
  - `GET /readyz`

## 当前明确未覆盖
- 预签名 URL
- virtual-host-style bucket
- Multipart Upload
- ACL / IAM / Versioning / Lifecycle
- 完整 checksum 校验

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
  "tenants": [
    {
      "id": "tenant-a",
      "accessKeyId": "demo-access-key",
      "secretAccessKey": "demo-secret-key",
      "upstreams": [
        {
          "id": "primary",
          "endpoint": "https://dav.example.com/remote.php/dav/files/demo",
          "username": "demo-user",
          "password": "demo-password",
          "rejectUnauthorized": true
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

## 本地运行
1. 安装依赖
2. 复制示例配置
3. 启动服务

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
```

## 模块边界
- `src/http`：HTTP 入口与健康检查
- `src/s3`：S3 协议解析、鉴权、XML 响应、错误模型
- `src/tenancy`：租户与 bucket 路由
- `src/webdav`：WebDAV 请求、路径映射、对象与列表适配
- `src/config`：配置加载与校验
- `src/observability`：请求日志与请求标识

## 语义注意点
- 当前仅支持 path-style bucket。
- `x-amz-content-sha256` 会参与签名校验，但不会对上传实体再做二次完整性校验。
- `ETag`、`Last-Modified` 等对象元信息以 WebDAV 上游实际返回为准，不强行伪造 S3 原生语义。