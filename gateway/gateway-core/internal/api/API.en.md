> English ｜ [中文](./API.md)

# Route Configuration Management API Documentation

> **Module**: `gateway-core/internal/api` — Route configuration management REST API
> **Version**: v1.0 (P0)
> **Base Path**: `/api/v1/routes`
> **Auth**: Admin Token (`X-Admin-Token` request header)

---

## 1. Overview

This API provides full lifecycle management of route configuration, including:
- Route table CRUD (single / full)
- Canary traffic-cutover control
- Configuration dry-run and version rollback
- Endpoint status query (P0 static view)
- Change audit and version history

### 1.1 General conventions

| Item | Description |
|------|------|
| Data format | `application/json; charset=utf-8` |
| Request body limit | 4 MiB (uniformly constrained by the `limitBody` middleware) |
| Error response | `{ "code": "<error code>", "message": "<description>" }` |
| Time format | Unix millisecond timestamp (int64) |
| Auth | All write operations require the `X-Admin-Token` header; reads depend on configuration |

### 1.2 Common error codes

| HTTP status | code | Description |
|------------|------|------|
| 400 | `invalid_request` | Request parameter or format error |
| 400 | `invalid_route` | Route configuration validation failed |
| 401 | `unauthorized` | Auth failed |
| 404 | `not_found` | Route does not exist |
| 409 | `conflict` | Version conflict (e.g. target version for rollback does not exist) |
| 500 | `internal_error` | Internal service error |

---

## 2. Route configuration API

### 2.1 Query full route table

```
GET /routes
```

Returns the currently effective full route table (with signature, for the data plane to pull and verify).

**Response example**:
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

### 2.2 Query a single route

```
GET /routes/{tenant}/{model}
```

**Path parameters**:
| Parameter | Type | Description |
|------|------|------|
| tenant | string | Tenant ID |
| model | string | Model name |

**Response example**:
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

**Error**: 404 `not_found` — route does not exist

### 2.3 Create/update a single route (Upsert)

```
PUT /routes/{tenant}/{model}
```

Creates or updates the route configuration for the given tenant-model. Overall version number increments + re-sign + write to audit chain.

**Request body**: `TableRoute` object (see §5 data model)

**Note**: the path parameters `tenant` and `model` override the same-named fields in the request body, preventing path/body inconsistency.

**Response example** (200 OK):
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

### 2.4 Delete a single route

```
DELETE /routes/{tenant}/{model}
```

Deletes the specified route configuration. Version increments + signature + audit.

**Response** (200 OK):
```json
{
  "version": 44,
  "deleted": {
    "tenant": "tenant-a",
    "model": "gpt-4"
  }
}
```

**Error**: 404 `not_found` — route does not exist

---

## 3. Configuration change API

### 3.1 Configuration dry-run

```
POST /routes/dry-run
```

Validates the configuration change and returns the diff, **without actually taking effect**. Used for pre-change verification.

**Request body**:
```json
{
  "action": "upsert" | "delete",
  "tenant": "tenant-a",
  "model": "gpt-4",
  "route": { ... }  // required for upsert
}
```

**Response** (200 OK):
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

**Validation failed** (400):
```json
{
  "valid": false,
  "errors": [
    {"field": "endpoints[0].weight", "message": "weight must be between 0 and 1"}
  ]
}
```

### 3.2 Version rollback

```
POST /routes/rollback
```

Rolls the route table back to a specified historical version. The rollback itself produces a new version number (does not overwrite history).

**Request body**:
```json
{
  "target_version": 40,
  "reason": "rollback reason (for audit)"
}
```

**Response** (200 OK):
```json
{
  "previous_version": 45,
  "new_version": 46,
  "rolled_back_to": 40
}
```

**Error**: 400 `invalid_request` — target version does not exist or is the current version

### 3.3 Version history

```
GET /routes/history?limit=20&offset=0
```

Queries the route-table version history + audit chain.

**Query parameters**:
| Parameter | Type | Default | Description |
|------|------|------|------|
| limit | int | 20 | Items per page (max 100) |
| offset | int | 0 | Offset |

**Response**:
```json
{
  "total": 46,
  "versions": [
    {
      "version": 46,
      "action": "rollback",
      "target_version": 40,
      "reason": "rollback reason",
      "timestamp": 1728000100,
      "operator": "admin"
    },
    ...
  ]
}
```

### 3.4 Configuration push (P0 empty implementation)

```
POST /routes/push
```

In the P0 phase the data plane uses the **active pull** model, so this interface is an empty implementation (keeps the interface placeholder).
The P1 phase will support the control plane actively pushing changes to the data plane.

**Response** (200 OK):
```json
{
  "pushed": false,
  "note": "P0 phase data plane actively pulls, push feature implemented in P1"
}
```

---

## 4. Status and audit API

### 4.1 Endpoint status query

```
GET /routes/endpoints/status
```

Queries the running status of all endpoints. P0 is a **configuration static view** (only returns the endpoint list from config),
P1 will integrate real-time health-status data.

**Response**:
```json
{
  "endpoints": [
    {
      "name": "ep-1",
      "url": "https://...",
      "enabled": true,
      "health": "unknown"  // P0 fixed to unknown
    }
  ]
}
```

### 4.2 Route change audit log

```
GET /routes/audit?limit=50&offset=0&tenant=&model=
```

Queries the audit log of route-configuration changes.

**Query parameters**:
| Parameter | Type | Default | Description |
|------|------|------|------|
| limit | int | 50 | Items per page |
| offset | int | 0 | Offset |
| tenant | string | — | Filter by tenant (optional) |
| model | string | — | Filter by model (optional) |

**Response**:
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
      "change_summary": "weight adjustment: ep-1 0.7→0.5, ep-2 0.3→0.5"
    }
  ]
}
```

---

## 5. Data model

### 5.1 TableRoute (route configuration)

| Field | Type | Required | Description |
|------|------|------|------|
| tenant | string | ✅ | Tenant ID |
| model | string | ✅ | Model name |
| default_engine | string | ✅ | Default engine (v1 binary-mode compatible) |
| fallback_engine | string | — | Fallback engine (v1 binary-mode compatible) |
| strategy | string | — | Routing strategy: `priority` / `weighted` / `failure-aware` (default `weighted`) |
| endpoints | TableEndpoint[] | — | Multi-endpoint list (enables multi-endpoint mode when non-empty) |
| canary | RouteCanary | — | Canary traffic-cutover config |
| enabled | bool | — | Whether enabled (default true) |

### 5.2 TableEndpoint (endpoint configuration)

| Field | Type | Required | Description |
|------|------|------|------|
| name | string | ✅ | Endpoint name (unique identifier) |
| url | string | — | Endpoint address |
| weight | float64 | — | Weight (0-1), proportionally distributed within the same priority |
| priority | int | — | Priority (smaller number = higher, 1 = primary) |
| enabled | bool | — | Whether enabled (default true) |
| auth | EndpointAuth | — | Endpoint credential config |

### 5.3 EndpointAuth (endpoint credential)

| Field | Type | Description |
|------|------|------|
| type | string | Auth type: `bearer` / `apikey` / `none` |
| secret_ref | string | Key reference: `km://<path>` / `env://<name>` (P0 supports the first two) |

### 5.4 RouteCanary (canary configuration)

| Field | Type | Default | Description |
|------|------|------|------|
| enabled | bool | false | Whether canary is enabled |
| target_endpoint | string | — | Target canary endpoint name |
| target_weight | float64 | 0.1 | Target canary weight (0-1) |
| ramp_step | float64 | 0.05 | Each ramp step |
| ramp_interval_ms | int64 | 60000 | Ramp interval (ms) |
| rollback_threshold | float64 | 0.1 | Auto-rollback failure-rate threshold |
| rollback_min_samples | int64 | 100 | Rollback minimum samples |
| allowed_tenants | string[] | [] | Tenant whitelist (empty = all tenants participate) |

---

## 6. Routing strategy description

### 6.1 Strategy types

| Strategy | Description | Applicable scenario |
|------|------|----------|
| `priority` | Primary-backup mode: select the highest-priority group of endpoints | Primary-backup switchover, disaster recovery |
| `weighted` | Weight mode: distribute proportionally by weight within the same priority group | Traffic distribution, A/B testing |
| `failure-aware` | Failure-rate aware: dynamic weight + circuit breaker + auto-recovery | Production high availability (recommended) |

### 6.2 Degradation ladder

```
L1 prescription (X-Otp-Route request header, used after signature verification)
  ↓ fails/missing
L2 default route-table cache (routecache, anti-rollback / anti-tamper)
  ↓ no hit
L3 fail-closed (503, no silent direct connect)
```

---

## 7. Deployment configuration

### 7.1 Related environment variables

| Variable | Description | Default |
|------|------|--------|
| `ROUTE_SIGNING_KEY` | Route-table signing key (base64) | — (required) |
| `ROUTE_FETCH_INTERVAL_MS` | Data-plane pull interval | 30000 |
| `CRYPTO_PROFILE` | Signature algorithm config (intl/sm-software) | intl |

### 7.2 Data-plane pull description

The data plane (otpmask Wasm plugin) actively pulls the route table via `GET /routes`, flow:
1. Periodically trigger pull (default 30s)
2. Verify signature (HMAC, key shared with control plane)
3. Monotonically increasing version-number validation (anti-rollback)
4. Pass → atomically replace local cache
5. Fail → keep old cache, log
