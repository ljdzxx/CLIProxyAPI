# 新增管理 API：Codex OAuth 预设参数登录

本文档说明新增接口 `POST /v0/management/codex-auth-url`。

该接口用于启动 Codex OAuth 登录，并在 Codex 认证文件保存前，把调用方预先传入的认证文件参数写入认证记录。认证文件落盘后会自带这些字段，后续 watcher / runtime 加载时会自动使用这些配置。

## 鉴权

该接口属于 Management API，必须携带管理密钥：

```http
Authorization: Bearer <management-key>
```

也兼容：

```http
X-Management-Key: <management-key>
```

如果从非 localhost 访问，还需要后端配置允许远程管理访问。

## 请求

```http
POST /v0/management/codex-auth-url
Content-Type: application/json
Authorization: Bearer <management-key>
```

可选 query 参数：

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `is_webui` | boolean | 与现有 GET 接口一致。为 `true` 时后端会启动本地 callback forwarder，适合 Web UI / 远程浏览器场景。 |

JSON body 字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `proxy_url` | string | 否 | 认证文件级代理 URL。支持普通代理 URL，也支持现有系统约定的 `direct`。别名：`proxy-url`。 |
| `priority` | integer | 否 | 认证文件优先级。运行时会同步到 `Attributes["priority"]`。 |
| `headers` | object | 否 | 请求头对象，键和值都必须是字符串。运行时会同步为 `header:<name>` attributes。 |
| `excluded_models` | string[] | 否 | 该 Codex 认证文件排除的模型列表。会去重、转小写，并与全局 OAuth 排除模型一起参与运行时模型过滤。别名：`excluded-models`。 |
| `rate_limit_max_requests` | integer | 否 | 本地请求限流最大请求数，必须为非负整数。别名：`request_limit_max_requests`。 |
| `rate_limit_window_seconds` | integer | 否 | 本地请求限流窗口秒数，必须为非负整数。别名：`request_limit_window_seconds`。 |

空 JSON `{}` 也合法，行为等同于启动 Codex OAuth，但不预设额外字段。

## 示例

```bash
curl -X POST "http://127.0.0.1:8317/v0/management/codex-auth-url?is_webui=true" \
  -H "Authorization: Bearer <management-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "proxy_url": "http://127.0.0.1:7890",
    "priority": 10,
    "headers": {
      "User-Agent": "codex-cli/0.0.0",
      "X-Custom-Header": "custom-value"
    },
    "excluded_models": ["gpt-5.4", "o4-mini"],
    "rate_limit_max_requests": 100,
    "rate_limit_window_seconds": 3600
  }'
```

## 成功响应

```json
{
  "status": "ok",
  "url": "https://auth.openai.com/oauth/authorize?...",
  "state": "<oauth-state>"
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `url` | Codex OAuth 授权 URL。调用方需要打开该 URL 完成授权。 |
| `state` | 本次 OAuth 会话状态。后续可用 `/v0/management/get-auth-status?state=<state>` 查询结果。 |

## 回调与状态查询

完成授权后，仍复用现有回调机制：

1. 浏览器跳转到 Codex callback URL。
2. 如果后端 callback forwarder 能收到回调，会自动写入 OAuth callback 文件。
3. 如果是远程浏览器场景，也可以把完整 callback URL 提交到：

```http
POST /v0/management/oauth-callback
```

body 示例：

```json
{
  "provider": "codex",
  "redirect_url": "http://localhost:1455/auth/callback?code=...&state=..."
}
```

查询状态：

```http
GET /v0/management/get-auth-status?state=<oauth-state>
```

状态返回：

| 状态 | 说明 |
| --- | --- |
| `wait` | OAuth 流程仍在等待回调或保存。 |
| `ok` | OAuth 已完成；认证文件已保存。 |
| `error` | OAuth 失败，`error` 字段包含失败原因。 |

## 落盘行为

当 Codex 授权码换 token 成功后，后端会先构造 Codex 认证记录，再把本接口传入的预设字段合并到认证记录中，最后才写入认证文件。

因此新生成的 Codex JSON 认证文件会直接包含这些顶层字段，例如：

```json
{
  "type": "codex",
  "email": "user@example.com",
  "account_id": "...",
  "access_token": "...",
  "refresh_token": "...",
  "proxy_url": "http://127.0.0.1:7890",
  "priority": 10,
  "headers": {
    "User-Agent": "codex-cli/0.0.0"
  },
  "excluded_models": ["gpt-5.4", "o4-mini"],
  "rate_limit_max_requests": 100,
  "rate_limit_window_seconds": 3600
}
```

同时，保存前会同步运行时字段：

| 配置 | 同步结果 |
| --- | --- |
| `proxy_url` | 写入 `Auth.ProxyURL`。 |
| `priority` | 写入 `Auth.Attributes["priority"]`。 |
| `headers` | 写入 `Auth.Attributes["header:<name>"]`。 |
| `excluded_models` | 写入 `Auth.Attributes["excluded_models"]` 和 `excluded_models_hash`。 |
| `rate_limit_*` | 写入 `Auth.Metadata`，运行时请求限流读取该 metadata。 |

## 错误响应

常见错误：

| HTTP 状态码 | 示例错误 | 说明 |
| --- | --- | --- |
| `400` | `invalid request body` | 请求体不是合法 JSON object。 |
| `400` | `unsupported field: access_token` | 请求体包含不支持的字段。 |
| `400` | `field headers must be an object with string values` | `headers` 不是字符串键值对象。 |
| `400` | `field rate_limit_max_requests must be a non-negative integer` | 请求限流字段不是非负整数。 |
| `401` | `missing management key` / `invalid management key` | 未提供或提供了错误的管理密钥。 |
| `403` | `remote management disabled` | 远程管理未启用。 |

