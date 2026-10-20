// Package a2aregistry 实现 P2-2 的 A2A 控制面：Agent 注册中心（Registry）。
//
// 职责（冻结清单 F-3/F-4/F-5）：
//   - SQLite 持久化（modernc.org/sqlite，WAL，单写者 BEGIN IMMEDIATE，registry_revision 单调）
//   - AgentCard v1.0 模型校验 + 网关形态 URL 校验（不重写、不重签）
//   - pinned 公钥信任模型验签（jku 非信任源、alg allowlist、轮换/吊销）
//   - 控制面 API /v1/a2a/*（角色授权、revision/ETag/If-Match/幂等）
//   - 内部快照分发 /internal/a2a/snapshot（数据面 fail-closed 取数）
//   - 健康检查字段 a2a_registry_ready/revision/db
//
// 数据面（gateway/a2aproxy）以本注册中心的快照为唯一事实源，本包不直接处理 A2A 流量。
package a2aregistry
