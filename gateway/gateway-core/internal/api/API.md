> 中文版 ｜ [English](./API.en.md)

# 路由配置管理 API 文档

> **模块**：`gateway-core/internal/api` — 路由配置管理 REST API
> **版本**：v1.0（P0）
> **Base Path**：`/api/v1/routes`
> **鉴权**：Admin Token（`X-Admin-Token` 请求头）

---

## 1. 概述

本 API 提供路由配置的全生命周期管理能力，包括：
- 路由表 CRUD（单条 / 全量）
- 灰度切流控制
- 配置预演（dry-run）与版本回滚
- 端点状态查询（P0 静态视图）
- 变更审计与版本历史

### 1.1 通用约定

| 项目 | 说明 |
|------|------|
| 数据格式 | `application/json; charset=utf-8` |
| 请求体上限 | 4 MiB（由 `limitBody` 中间件统一约束） |
| 错误响应 | `{ "code": "<错误码>", "message": "<描述>" }` |
| 时间格式 | Unix 毫秒时间戳（int64） |
| 鉴权 | 所有写操作需 `X-Admin-Token` 头；读操作视配置而定 |

### 1.2 通用错误码

| HTTP 状态码 | code | 说明 |
|------------|------|------|
| 400 | `invalid_request` | 请求参数或格式错误 |
| 400 | `invalid_route` | 路由配置校验失败 |
| 401 | `unauthorized` | 鉴权失败 |
| 404 | `not_found` | 路由不存在 |
| 409 | `conflict` | 版本冲突（rollback 时目标版本不存在等） |
| 500 | `internal_error` | 服务内部错误 |

---

## 2. 路由配置 API

### 2.1 查询完整路由表

```
GET /routes
```

返回当前生效的完整路由表（含签名，供数据面拉取验证）。

**响应示例**：
```json
{
  "version": 42,
  "signature": "base64_encoded_signature",
  "sign_alg": "HMAC-SHA256",
  "updated_at": 1728000000,
  "routes": [
    {
      "tenant": "tenant-a",
      "model": "gpt-4",
      "default_engine": "ai-proxy-a",
      "fallback_engine": "ai-proxy-b",
      "strategy": "failure-aware",
      "endpoints": [
        {"name": "ep-1", "url": "https://...", "weight": 0.7, "priority": 1, "enabled": true},
        {"name": "ep-2", "url": "https://...", "weight": 0.3, "priority": 1, "enabled": true}
      ]
    }
  ]
}
```

### 2.2 查询单条路由

```
GET /routes/{tenant}/{model}
```

**路径参数**：
| 参数 | 类型 | 说明 |
|------|------|------|
| tenant | string | 租户 ID |
| model | string | 模型名称 |

**响应示例**：
```json
{
  "version": 42,
  "route": {
    "tenant": "tenant-a",
    "model": "gpt-4",
    "default_engine": "ai-proxy-a",
    "strategy": "weighted",
    "endpoints": [...]
  }
}
```

**错误**：404 `not_found` — 路由不存在

### 2.3 创建/更新单条路由（Upsert）

```
PUT /routes/{tenant}/{model}
```

创建或更新指定租户-模型的路由配置。整体版本号递增 + 重新签名 + 落审计链。

**请求体**：`TableRoute` 对象（见 §5 数据模型）

**注意**：路径参数 `tenant` 和 `model` 会覆盖请求体中的同名字段，防止路径与 body 不一致。

**响应示例**（200 OK）：
```json
{
  "version": 43,
  "route": {...},
  "diff": {
    "old": {...},
    "new": {...}
  }
}
```

### 2.4 删除单条路由

```
DELETE /routes/{tenant}/{model}
```

删除指定路由配置。版本号递增 + 签名 + 审计。

**响应**（200 OK）：
```json
{
  "version": 44,
  "deleted": {
    "tenant": "tenant-a",
    "model": "gpt-4"
  }
}
```

**错误**：404 `not_found` — 路由不存在

---

## 3. 配置变更 API

### 3.1 配置预演（Dry-Run）

```
POST /routes/dry-run
```

校验配置变更并返回 diff，**不实际生效**。用于变更前验证。

**请求体**：
```json
{
  "action": "upsert" | "delete",
  "tenant": "tenant-a",
  "model": "gpt-4",
  "route": { ... }  // upsert 时需要
}
```

**响应**（200 OK）：
```json
{
  "valid": true,
  "action": "upsert",
  "diff": {
    "old": {...},
    "new": {...},
    "changes": ["endpoints[0].weight: 0.7 → 0.5", "..."]
  },
  "new_version": 45
}
```

**校验失败**（400）：
```json
{
  "valid": false,
  "errors": [
    {"field": "endpoints[0].weight", "message": "权重必须在 0-1 之间"}
  ]
}
```

### 3.2 版本回滚

```
POST /routes/rollback
```

将路由表回滚到指定历史版本。回滚本身产生新版本号（不覆盖历史）。

**请求体**：
```json
{
  "target_version": 40,
  "reason": "回滚原因（审计用）"
}
```

**响应**（200 OK）：
```json
{
  "previous_version": 45,
  "new_version": 46,
  "rolled_back_to": 40
}
```

**错误**：400 `invalid_request` — 目标版本不存在或为当前版本

### 3.3 版本历史

```
GET /routes/history?limit=20&offset=0
```

查询路由表版本历史 + 审计链。

**查询参数**：
| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| limit | int | 20 | 每页数量（最大 100） |
| offset | int | 0 | 偏移量 |

**响应**：
```json
{
  "total": 46,
  "versions": [
    {
      "version": 46,
      "action": "rollback",
      "target_version": 40,
      "reason": "回滚原因",
      "timestamp": 1728000100,
      "operator": "admin"
    },
    ...
  ]
}
```

### 3.4 配置推送（P0 空实现）

```
POST /routes/push
```

P0 阶段数据面采用**主动拉取**模式，此接口为空实现（保留接口占位）。
P1 阶段将支持控制面主动推送变更到数据面。

**响应**（200 OK）：
```json
{
  "pushed": false,
  "note": "P0 阶段数据面主动拉取，推送功能 P1 实现"
}
```

---

## 4. 状态与审计 API

### 4.1 端点状态查询

```
GET /routes/endpoints/status
```

查询所有端点的运行状态。P0 为**配置静态视图**（仅返回配置中的端点列表），
P1 将对接实时健康状态数据。

**响应**：
```json
{
  "endpoints": [
    {
      "name": "ep-1",
      "url": "https://...",
      "enabled": true,
      "health": "unknown"  // P0 固定为 unknown
    }
  ]
}
```

### 4.2 路由变更审计日志

```
GET /routes/audit?limit=50&offset=0&tenant=&model=
```

查询路由配置变更的审计日志。

**查询参数**：
| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| limit | int | 50 | 每页数量 |
| offset | int | 0 | 偏移量 |
| tenant | string | — | 按租户过滤（可选） |
| model | string | — | 按模型过滤（可选） |

**响应**：
```json
{
  "total": 128,
  "logs": [
    {
      "timestamp": 1728000000,
      "version": 42,
      "action": "upsert",
      "tenant": "tenant-a",
      "model": "gpt-4",
      "operator": "admin",
      "change_summary": "权重调整: ep-1 0.7→0.5, ep-2 0.3→0.5"
    }
  ]
}
```

---

## 5. 数据模型

### 5.1 TableRoute（路由配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| tenant | string | ✅ | 租户 ID |
| model | string | ✅ | 模型名称 |
| default_engine | string | ✅ | 默认引擎（v1 二元模式兼容） |
| fallback_engine | string | — | 降级引擎（v1 二元模式兼容） |
| strategy | string | — | 路由策略：`priority` / `weighted` / `failure-aware`（默认 `weighted`） |
| endpoints | TableEndpoint[] | — | 多端点列表（非空时启用多端点模式） |
| canary | RouteCanary | — | 灰度切流配置 |
| enabled | bool | — | 是否启用（默认 true） |

### 5.2 TableEndpoint（端点配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| name | string | ✅ | 端点名称（唯一标识） |
| url | string | — | 端点地址 |
| weight | float64 | — | 权重（0-1），同优先级内按比例分配 |
| priority | int | — | 优先级（数字越小越高，1=主） |
| enabled | bool | — | 是否启用（默认 true） |
| auth | EndpointAuth | — | 端点凭证配置 |

### 5.3 EndpointAuth（端点凭证）

| 字段 | 类型 | 说明 |
|------|------|------|
| type | string | 认证类型：`bearer` / `apikey` / `none` |
| secret_ref | string | 密钥引用：`km://<path>` / `env://<name>`（P0 支持前两种） |

### 5.4 RouteCanary（灰度配置）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| enabled | bool | false | 是否启用灰度 |
| target_endpoint | string | — | 灰度目标端点名称 |
| target_weight | float64 | 0.1 | 目标灰度权重（0-1） |
| ramp_step | float64 | 0.05 | 每次放量步长 |
| ramp_interval_ms | int64 | 60000 | 放量间隔（毫秒） |
| rollback_threshold | float64 | 0.1 | 自动回滚失败率阈值 |
| rollback_min_samples | int64 | 100 | 回滚最小样本数 |
| allowed_tenants | string[] | [] | 租户白名单（空=所有租户均参与） |

---

## 6. 路由策略说明

### 6.1 策略类型

| 策略 | 说明 | 适用场景 |
|------|------|----------|
| `priority` | 主备模式：按优先级选最高组的端点 | 主备切换、灾备 |
| `weighted` | 权重模式：同优先级组内按权重比例分配 | 流量分配、AB 测试 |
| `failure-aware` | 失败率感知：动态权重 + 熔断 + 自动恢复 | 生产环境高可用（推荐） |

### 6.2 降级阶梯

```
L1 处方（X-Otp-Route 请求头，验签后使用）
  ↓ 失效/缺失
L2 默认路由表缓存（routecache，防回滚/防篡改）
  ↓ 无命中
L3 fail-closed（503，不静默直连）
```

---

## 7. 部署配置

### 7.1 相关环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ROUTE_SIGNING_KEY` | 路由表签名密钥（base64） | —（必填） |
| `ROUTE_FETCH_INTERVAL_MS` | 数据面拉取间隔 | 30000 |
| `CRYPTO_PROFILE` | 签名算法配置（intl/sm-software） | intl |

### 7.2 数据面拉取说明

数据面（otpmask Wasm 插件）通过 `GET /routes` 主动拉取路由表，流程：
1. 周期触发拉取（默认 30s）
2. 验签（HMAC，密钥与控制面共享）
3. 版本号单调递增校验（防回滚）
4. 通过 → 原子替换本地缓存
5. 失败 → 保留旧缓存，记录日志
