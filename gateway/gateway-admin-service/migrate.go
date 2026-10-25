// Package main — P2-4 T-1.6 存储迁移工具（sqlite 源 → 共享库目标）。
//
// 目的：把**单副本 sqlite 部署**的历史数据搬到**多副本共享库**（PG），支撑
// P2-4 多集群管理。内建于 admin-service，不引入外部二进制；未显式调用即零副作用。
//
// 命令（admin-service migrate ...）：
//
//	plan     列出待迁移表、两端行数与校验和（只读，不写任何库）
//	export   从源（sqlite，只读）导出到 dump 文件（JSON）
//	import   把 dump 导入目标库（**默认 dry-run**；-apply 才真正写入）
//	verify   逐表比对源/目标的行数与内容摘要；不通过则不得切换
//	rollback 打印回滚 SOP；-purge 时清除目标库本次导入的行
//
// 幂等可重入：import 走 `INSERT ... ON CONFLICT (pk) DO UPDATE`（upsert 语义），
// 重复执行不产生重复行/脏数据，校验和保持一致；export 覆盖写同一 dump 文件。
//
// 序列一致性：PG 侧 BIGSERIAL 列在导入后回填序列（setval），避免后续插入主键冲突。
//
// 源库分组（P2-4 T-1.6 补）：sqlite 部署下**集群注册表在独立文件**
// （ADMIN_CLUSTER_STORE_PATH，缺省 <TENANT_STORE_PATH>.clusters），不在租户库文件内；
// PG 部署则与租户库同库（TENANT_STORE_PG_DSN）。因此迁移有两个源：
//   - 默认源（-from）：租户表 + 安全计数器表；
//   - 集群注册表源（-from-cluster，缺省推导 <from>.clusters）：clusters /
//     cluster_heartbeats / cluster_credentials。
//
// **集群注册表必须随迁**（否则切库即丢集群拓扑、集群身份凭证失效 → 心跳被
// fail-closed 拒绝 → 注册表状态机直接 degraded/unreachable）；
// 集群注册表源文件不存在时该组表跳过（未启用集群注册表的部署），
// 显式 -from-cluster 指向不存在路径则 fail-closed。
//
// 回滚语义：rollback 默认只打印 SOP；-purge 按 dump 中的主键**精确删除本次导入的行**
// （不动目标库既有数据；缺 dump 则 fail-closed 拒绝执行清除）。
//
// 已知口径（MFA）：mfa_states **不迁移**——MFA 属等保强制的 step-up 控制，
// 状态内含 TOTP 种子信封密文与应急码摘要，跨库搬迁需同一主密钥且不放大密钥
// 暴露面；切换到共享库后已绑定账号须**重新 enroll**（见 mfa.go 注记与本文件
// migrateMFAReason）。plan/verify 会列出该表并标注"不迁移"。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// migrateDumpVersion dump 文件格式版本（不兼容变更时递增）。
const migrateDumpVersion = 1

// migrateMFAReason MFA 表不迁移的口径说明（plan/verify 输出与日志均引用）。
const migrateMFAReason = "不迁移：MFA 为等保强制 step-up 控制，状态含 TOTP 种子信封密文；切换后已绑定账号须重新 enroll"

// migrateTableSpec 迁移表规格：表名 + 主键列（upsert 依据）+ 自增列（序列回填）。
type migrateTableSpec struct {
	name string
	pk   string // 主键列（单列主键表）
	// pkCols 复合主键列（非空时优先于 pk）。P2-4 T-3.2a 起
	// tenant_dispatch_state 的主键为 (tenant_id, cluster_id)。
	pkCols []string
	serial string // 自增列名；空 = 无自增
	skip   string // 非空 = 不迁移（口径原因），仅 plan/verify 列出
	source string // 源库分组："" = 默认源（-from）；"cluster" = 集群注册表源（-from-cluster）
}

// pkColumns 返回该表的主键列序列（复合主键优先）。
func (s migrateTableSpec) pkColumns() []string {
	if len(s.pkCols) > 0 {
		return s.pkCols
	}
	return []string{s.pk}
}

// migrateSourceCluster 集群注册表源分组标识（T-2.1/T-2.3 的表在 sqlite 部署下
// 位于独立文件 <TENANT_STORE_PATH>.clusters，不与租户库同文件）。
const migrateSourceCluster = "cluster"

// migrateTables 迁移范围：T-1.2 的 11 张租户表 + T-1.3/T-1.4/T-1.5 的安全计数器表
// + mfa_states（不迁移，仅登记口径）。
var migrateTables = []migrateTableSpec{
	// ---- 租户门户表（T-1.2，§3.5）----
	{name: "tenants", pk: "id"},
	{name: "tenant_users", pk: "id", serial: "id"},
	{name: "mail_action_tokens", pk: "token_hash"},
	{name: "register_rate", pk: "ip"},
	{name: "api_keys", pk: "key_id"},
	{name: "policy_overlays", pk: "tenant_id"},
	{name: "model_configs", pk: "tenant_id"},
	{name: "subscription_requests", pk: "request_id"},
	{name: "tenant_provisionings", pk: "tenant_id"},
	{name: "tenant_statements", pk: "statement_id"},
	// P2-4 T-3.2a：主键迁移为复合键 (tenant_id, cluster_id)——
	// upsert / purge 均按复合键定位，"每租户×每集群"各占一行。
	{name: "tenant_dispatch_state", pk: "tenant_id", pkCols: []string{"tenant_id", "cluster_id"}},
	// ---- 安全计数器表（T-1.3/T-1.4/T-1.5）----
	{name: "captcha_rate_limits", pk: "ip"},
	{name: "captcha_challenges", pk: "id"},
	{name: "login_attempts", pk: "identity"},
	{name: "operation_intervals", pk: "op_key"},
	{name: "mfa_states", pk: "sub", skip: migrateMFAReason},
	// ---- 集群注册表（P2-4 T-2.1/T-2.3）----
	//
	// 口径（必须随迁，否则切库即丢集群拓扑）：
	//   - clusters：控制面集群注册表（id/端点/形态/容量/状态）。不迁 → 目标库
	//     ensureSchema 建出空表 → 已注册集群全部"消失"，调度与下发无目标。
	//   - cluster_credentials：集群身份凭证（只存哈希）。不迁 → 切库后所有集群
	//     心跳被 fail-closed 拒绝 → 注册表状态机直接 degraded/unreachable。
	//   - cluster_heartbeats：心跳明细（含 applied_config_version 历史）。
	//     不迁 → T-3.3 收敛核对失去"实际上报版本"的历史证据链。
	// 注：sqlite 部署下这三张表在独立文件（-from-cluster）；PG 部署与租户库同库。
	{name: "clusters", pk: "id", source: migrateSourceCluster},
	{name: "cluster_heartbeats", pk: "seq", serial: "seq", source: migrateSourceCluster},
	{name: "cluster_credentials", pk: "id", source: migrateSourceCluster},
}

// migrateTableDump 单表导出内容（含校验和，供 import 前自检）。
type migrateTableDump struct {
	Name     string   `json:"name"`
	PK       string   `json:"pk"`
	Columns  []string `json:"columns"`
	Rows     [][]any  `json:"rows"`
	Count    int      `json:"count"`
	Checksum string   `json:"checksum"`
	Skipped  string   `json:"skipped,omitempty"` // 非迁移表的口径原因
}

// migrateDump dump 文件结构。
type migrateDump struct {
	Version     int                         `json:"version"`
	GeneratedAt int64                       `json:"generated_at"`
	Source      string                      `json:"source"`
	Tables      map[string]migrateTableDump `json:"tables"`
}

// migrateOptions 迁移命令参数。
type migrateOptions struct {
	action      string   // plan|export|import|verify|rollback
	from        string   // 源 sqlite 路径
	fromCluster string   // 集群注册表源 sqlite 路径（缺省 = <from>.clusters，不存在则该组表跳过）
	to          string   // 目标 DSN
	toDriver    string   // 目标方言：pgx|sqlite
	out         string   // dump 文件（export 写 / import 读）
	apply       bool     // import 真正写入（默认 dry-run）
	purge       bool     // rollback 清除目标库已导入行
	tables      []string // 限定表（空 = 全部）
}

// migrateUsage 命令用法与双跑/切换 SOP（help 与错误信息共用）。
const migrateUsage = `用法：admin-service migrate -action <plan|export|import|verify|rollback> [选项]

  -action   plan     列出待迁移表、两端行数与校验和（只读）
            export   源（sqlite，只读）→ dump 文件
            import   dump → 目标库（默认 dry-run；-apply 才写入）
            verify   逐表比对源/目标行数与内容摘要（不通过即不得切换）
            rollback 打印回滚 SOP；-purge 按 dump 主键清除**本次导入的行**
                      （须带 -out 指定 dump；缺 dump → fail-closed 不清库）
  -from     源 sqlite 文件路径（以 query_only 打开，导出侧只读）
  -from-cluster  集群注册表源 sqlite 路径（缺省 = <from>.clusters；不存在则集群组表跳过）
  -to       目标 DSN（PG 连接串或 sqlite 路径）
  -driver   目标方言：pgx（默认）| sqlite（影子库演练用）
  -out      dump 文件路径（默认 migrate-dump.json）
  -apply    import 真正写入目标库（缺省 dry-run）
  -purge    rollback 时清除目标库已导入行（缺省仅打印 SOP）
  -tables   限定表名（逗号分隔；缺省全部）

双跑/切换 SOP（命令序列）：
  1) 双跑期：两套库并存、写入仍走 sqlite。
     admin-service migrate -action plan    -from <sqlite> -to <dsn>
  2) 导出 + 试导入（dry-run 看差异，不写库）：
     admin-service migrate -action export  -from <sqlite> -out dump.json
     admin-service migrate -action import  -to <dsn> -out dump.json
  3) 正式导入（幂等，可重入）：
     admin-service migrate -action import  -to <dsn> -out dump.json -apply
  4) 对账：admin-service migrate -action verify -from <sqlite> -to <dsn>
     —— 校验和不通过**不得**切换（退出码 1）。
  5) 切换：把 SECURITY_STORE_PG_DSN / 租户库方言切到 PG 并滚动重启；
     观察一个完整业务周期。
  6) 回滚：DNS/env 切回 sqlite（进程内实现），共享库数据保留待对账；
     确需清除目标库导入行时：
     admin-service migrate -action rollback -to <dsn> -purge -out dump.json

  注：sqlite 部署下集群注册表在独立文件（<sqlite>.clusters），迁移工具会自动
  推导该源；如路径不同，显式加 -from-cluster <path>。

  schema 演进口径：导出前须让**源实例已运行新版本**（新版本启动即补齐新增列，
  如 T-3.1 的 policy_overlays.scope / model_configs.scope / tenant_provisionings.scope）。
  源仍是旧 schema 时 import 会以"目标列在 dump 中缺失（schema 漂移）"fail-closed
  拒绝——这是有意为之：宁可拒绝切换，也不把旧 schema 的行静默写成缺列数据。
  处理办法：先滚动升级源实例（启动即补列），再重新 export/import/verify。
`

// runMigrate 迁移命令入口（main.go 分派）；返回进程退出码。
func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, migrateUsage) }
	opt := &migrateOptions{}
	fs.StringVar(&opt.action, "action", "plan", "plan|export|import|verify|rollback")
	fs.StringVar(&opt.from, "from", "", "源 sqlite 文件路径")
	fs.StringVar(&opt.fromCluster, "from-cluster", "", "集群注册表源 sqlite 路径（缺省 <from>.clusters）")
	fs.StringVar(&opt.to, "to", "", "目标 DSN")
	fs.StringVar(&opt.toDriver, "driver", string(sqlutil.Postgres), "pgx|sqlite")
	fs.StringVar(&opt.out, "out", "migrate-dump.json", "dump 文件路径")
	fs.BoolVar(&opt.apply, "apply", false, "import 真正写入（默认 dry-run）")
	fs.BoolVar(&opt.purge, "purge", false, "rollback 清除目标库已导入行")
	var tables string
	fs.StringVar(&tables, "tables", "", "限定表（逗号分隔）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(tables) != "" {
		opt.tables = strings.Split(tables, ",")
	}
	specs, err := migrateSelectedTables(opt.tables)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}

	switch opt.action {
	case "plan":
		return migrateRunPlan(opt, specs)
	case "export":
		return migrateRunExport(opt, specs)
	case "import":
		return migrateRunImport(opt, specs)
	case "verify":
		return migrateRunVerify(opt, specs)
	case "rollback":
		return migrateRunRollback(opt, specs)
	default:
		fmt.Fprintf(os.Stderr, "migrate: 未知 action %q\n\n%s", opt.action, migrateUsage)
		return 2
	}
}

// migrateSelectedTables 解析 -tables（空 = 全部；未知表名 → 报错 fail-closed）。
func migrateSelectedTables(names []string) ([]migrateTableSpec, error) {
	if len(names) == 0 {
		return migrateTables, nil
	}
	out := make([]migrateTableSpec, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		found := false
		for _, spec := range migrateTables {
			if spec.name == name {
				out = append(out, spec)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("未知表名 %q（迁移表白名单见 migrate.go）", name)
		}
	}
	return out, nil
}

// ---------- 打开库 ----------

// migrateOpenSource 打开源库：sqlite + query_only（导出侧只读，防误写历史数据）。
func migrateOpenSource(path string) (*sqlutil.DB, error) {
	if path == "" {
		return nil, errors.New("缺少 -from（源 sqlite 路径）")
	}
	dsn := "file:" + path + "?_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sqlutil.Open(sqlutil.SQLite, dsn, 0)
	if err != nil {
		return nil, fmt.Errorf("打开源库失败: %w", err)
	}
	return db, nil
}

// migrateOpenTarget 打开目标库（方言由 -driver 指定）。
func migrateOpenTarget(dsn, driver string) (*sqlutil.DB, error) {
	if dsn == "" {
		return nil, errors.New("缺少 -to（目标 DSN）")
	}
	d := sqlutil.ParseDialect(driver)
	db, err := sqlutil.Open(d, dsn, 0)
	if err != nil {
		return nil, fmt.Errorf("打开目标库失败: %w", err)
	}
	return db, nil
}

// ---------- 多源（租户库 + 集群注册表） ----------

// migrateSources 迁移源库集合：默认源（租户/安全表）+ 集群注册表源（T-2.1/T-2.3）。
type migrateSources struct {
	def     *sqlutil.DB // 默认源（-from）
	cluster *sqlutil.DB // 集群注册表源（-from-cluster）；nil = 未启用/文件不存在
}

// migrateOpenSources 打开迁移所需的源库集合。
//
// 集群注册表源路径：显式 -from-cluster 优先；缺省推导 <from>.clusters
// （与 config.go 中 ADMIN_CLUSTER_STORE_PATH 的缺省推导一致）。
// 文件不存在 → cluster=nil（该组表跳过）。**必须先判存在再打开**：sqlite 打开
// 不存在的路径会新建空库（query_only 也拦不住建库），会把"未启用集群注册表"的
// 部署凭空造出一个空源库。
func migrateOpenSources(opt *migrateOptions) (*migrateSources, error) {
	def, err := migrateOpenSource(opt.from)
	if err != nil {
		return nil, err
	}
	s := &migrateSources{def: def}
	clusterPath := opt.fromCluster
	if clusterPath == "" && opt.from != "" {
		clusterPath = opt.from + ".clusters"
	}
	if clusterPath == "" {
		return s, nil
	}
	if _, statErr := os.Stat(clusterPath); statErr != nil {
		if opt.fromCluster != "" {
			// 显式指定却不存在 → fail-closed（路径拼错不得静默跳过整组表）。
			_ = def.Close()
			return nil, fmt.Errorf("集群注册表源不存在: %s", clusterPath)
		}
		return s, nil
	}
	cdb, cerr := migrateOpenSource(clusterPath)
	if cerr != nil {
		_ = def.Close()
		return nil, fmt.Errorf("打开集群注册表源失败: %w", cerr)
	}
	s.cluster = cdb
	return s, nil
}

// forSpec 返回该表所属的源库句柄（cluster 分组 → 集群注册表源；nil = 该源不可用）。
func (s *migrateSources) forSpec(spec migrateTableSpec) *sqlutil.DB {
	if spec.source == migrateSourceCluster {
		return s.cluster
	}
	return s.def
}

// close 关闭所有源库句柄。
func (s *migrateSources) close() {
	if s == nil {
		return
	}
	if s.cluster != nil {
		_ = s.cluster.Close()
	}
	if s.def != nil {
		_ = s.def.Close()
	}
}

// ---------- 读取与校验和 ----------

// migrateColumns 读取表列名（按表定义顺序）。sqlite 用 PRAGMA，PG 用 information_schema。
func migrateColumns(db *sqlutil.DB, table string) ([]string, error) {
	if db.Dialect().IsPostgres() {
		rows, err := db.Query(`SELECT column_name FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = ? ORDER BY ordinal_position`, table)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				return nil, err
			}
			cols = append(cols, c)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(cols) == 0 {
			return nil, fmt.Errorf("目标库缺表 %s（须先由应用侧 DDL 初始化）", table)
		}
		return cols, nil
	}
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("表不存在或无列: %s", table)
	}
	return cols, nil
}

// migrateTableExists 判断表是否存在（sqlite: sqlite_master；PG: information_schema）。
func migrateTableExists(db *sqlutil.DB, table string) (bool, error) {
	var n int
	if db.Dialect().IsPostgres() {
		if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = ?`, table).Scan(&n); err != nil {
			return false, err
		}
		return n > 0, nil
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// migrateCanonical 单值规范化（校验和与跨方言比对用）。
func migrateCanonical(v any) string {
	switch t := v.(type) {
	case nil:
		return "\x00"
	case string:
		return "s:" + t
	case []byte:
		return "b:" + string(t)
	case int64:
		return "i:" + strconv.FormatInt(t, 10)
	case float64:
		return "f:" + strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		return "b:" + strconv.FormatBool(t)
	case time.Time:
		return "t:" + t.UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("x:%T:%v", v, v)
	}
}

// migrateChecksum 按主键序对全部行做内容摘要（行数 + 逐行规范化值）。
func migrateChecksum(rows [][]any) string {
	h := sha256.New()
	for _, row := range rows {
		var b strings.Builder
		for i, v := range row {
			if i > 0 {
				b.WriteByte('\x1f')
			}
			b.WriteString(migrateCanonical(v))
		}
		b.WriteByte('\n')
		h.Write([]byte(b.String()))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// migrateReadTable 读取整表（按主键排序，保证两端顺序一致）。
func migrateReadTable(db *sqlutil.DB, spec migrateTableSpec) (migrateTableDump, error) {
	out := migrateTableDump{Name: spec.name, PK: strings.Join(spec.pkColumns(), ",")}
	if spec.skip != "" {
		out.Skipped = spec.skip
		return out, nil
	}
	cols, err := migrateColumns(db, spec.name)
	if err != nil {
		return out, err
	}
	out.Columns = cols
	q := fmt.Sprintf(`SELECT %s FROM %s ORDER BY %s`, strings.Join(cols, ", "), spec.name,
		strings.Join(spec.pkColumns(), ", "))
	rows, err := db.Query(q)
	if err != nil {
		return out, fmt.Errorf("读表 %s 失败: %w", spec.name, err)
	}
	defer rows.Close()
	for rows.Next() {
		buf := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range buf {
			ptrs[i] = &buf[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return out, fmt.Errorf("扫描表 %s 失败: %w", spec.name, err)
		}
		out.Rows = append(out.Rows, buf)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Count = len(out.Rows)
	out.Checksum = migrateChecksum(out.Rows)
	return out, nil
}

// ---------- 各 action ----------

// migrateRunPlan 只读列出两端行数与校验和（不写任何库）。
func migrateRunPlan(opt *migrateOptions, specs []migrateTableSpec) int {
	sources, err := migrateOpenSources(opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}
	defer sources.close()
	explicit := len(opt.tables) > 0
	fmt.Printf("迁移计划：源=%s 目标=%s(%s)\n", opt.from, opt.to, opt.toDriver)
	fmt.Printf("%-24s %8s %8s %-16s %s\n", "表", "源行数", "目标行数", "校验和(前8)", "备注")
	ok := true
	for _, spec := range specs {
		src := sources.forSpec(spec)
		if src == nil {
			if explicit {
				fmt.Fprintf(os.Stderr, "migrate: 集群注册表源不可用（-tables 显式指定，fail-closed）\n")
				return 1
			}
			fmt.Printf("%-24s 集群注册表源不可用（跳过）\n", spec.name)
			continue
		}
		if exists, err := migrateTableExists(src, spec.name); err == nil && !exists {
			fmt.Printf("%-24s 源库无此表（跳过）\n", spec.name)
			continue
		}
		sd, err := migrateReadTable(src, spec)
		if err != nil {
			fmt.Printf("%-24s 读取失败: %v\n", spec.name, err)
			ok = false
			continue
		}
		tgtCount := -1
		tgtSum := "-"
		if opt.to != "" {
			if dst, derr := migrateOpenTarget(opt.to, opt.toDriver); derr == nil {
				if td, terr := migrateReadTable(dst, spec); terr == nil {
					tgtCount = td.Count
					tgtSum = td.Checksum
				}
				dst.Close()
			}
		}
		sum := sd.Checksum
		if len(sum) > 8 {
			sum = sum[:8]
		}
		if len(tgtSum) > 8 {
			tgtSum = tgtSum[:8]
		}
		fmt.Printf("%-24s %8d %8d %-16s %s\n", spec.name, sd.Count, tgtCount, sum, migrateNote(spec, sum, tgtSum))
	}
	if !ok {
		return 1
	}
	return 0
}

// migrateNote plan 行备注（迁移口径/差异提示）。
func migrateNote(spec migrateTableSpec, srcSum, tgtSum string) string {
	if spec.skip != "" {
		return "不迁移"
	}
	if tgtSum == "-" {
		return "目标未连接"
	}
	if tgtSum == srcSum {
		return "一致"
	}
	return "不一致（须 import 后 verify）"
}

// migrateRunExport 导出源库到 dump 文件。
func migrateRunExport(opt *migrateOptions, specs []migrateTableSpec) int {
	sources, err := migrateOpenSources(opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}
	defer sources.close()
	dump := migrateDump{Version: migrateDumpVersion, GeneratedAt: time.Now().Unix(), Source: opt.from, Tables: map[string]migrateTableDump{}}
	explicit := len(opt.tables) > 0
	for _, spec := range specs {
		src := sources.forSpec(spec)
		if src == nil {
			if explicit {
				fmt.Fprintf(os.Stderr, "migrate: 导出失败: 集群注册表源不可用（-tables 显式指定，fail-closed）\n")
				return 1
			}
			fmt.Printf("导出 %-24s 集群注册表源不可用，跳过\n", spec.name)
			dump.Tables[spec.name] = migrateTableDump{Name: spec.name, PK: strings.Join(spec.pkColumns(), ","), Skipped: "集群注册表源不可用"}
			continue
		}
		exists, err := migrateTableExists(src, spec.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate: 导出失败: %v\n", err)
			return 1
		}
		if !exists {
			// 缺省（全表）时源库无此表视为尚未创建（安全计数器表在未启用过共享后端的
			// 部署里不存在）→ 跳过；显式 -tables 指定则 fail-closed 报错。
			if !explicit {
				fmt.Printf("导出 %-24s 源库无此表，跳过\n", spec.name)
				dump.Tables[spec.name] = migrateTableDump{Name: spec.name, PK: strings.Join(spec.pkColumns(), ","), Skipped: "源库无此表"}
				continue
			}
			fmt.Fprintf(os.Stderr, "migrate: 导出失败: 源库缺表 %s（-tables 显式指定，fail-closed）\n", spec.name)
			return 1
		}
		td, err := migrateReadTable(src, spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate: 导出失败: %v\n", err)
			return 1
		}
		dump.Tables[spec.name] = td
		fmt.Printf("导出 %-24s rows=%d checksum=%s\n", spec.name, td.Count, shortSum(td.Checksum))
	}
	raw, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: dump 序列化失败: %v\n", err)
		return 1
	}
	if err := os.WriteFile(opt.out, raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: 写 dump 失败: %v\n", err)
		return 1
	}
	fmt.Printf("导出完成：%s（表 %d 张）\n", opt.out, len(dump.Tables))
	return 0
}

// migrateRunImport 导入 dump 到目标库（默认 dry-run；-apply 才写入；upsert 幂等）。
func migrateRunImport(opt *migrateOptions, specs []migrateTableSpec) int {
	dump, err := migrateLoadDump(opt.out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}
	dst, err := migrateOpenTarget(opt.to, opt.toDriver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}
	defer dst.Close()
	mode := "dry-run（未写入，加 -apply 生效）"
	if opt.apply {
		mode = "写入"
	}
	fmt.Printf("导入 %s → %s(%s)：%s\n", opt.out, opt.to, opt.toDriver, mode)
	for _, spec := range specs {
		td, ok := dump.Tables[spec.name]
		if !ok {
			fmt.Printf("%-24s dump 中缺失，跳过\n", spec.name)
			continue
		}
		if td.Skipped != "" {
			fmt.Printf("%-24s %s\n", spec.name, td.Skipped)
			continue
		}
		if !opt.apply {
			fmt.Printf("%-24s 计划导入 rows=%d（dry-run）\n", spec.name, td.Count)
			continue
		}
		n, err := migrateImportTable(dst, spec, td)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate: 导入 %s 失败: %v\n", spec.name, err)
			return 1
		}
		fmt.Printf("%-24s 导入 rows=%d\n", spec.name, n)
	}
	if opt.apply {
		if err := migrateFixSequences(dst, specs); err != nil {
			fmt.Fprintf(os.Stderr, "migrate: 序列回填失败: %v\n", err)
			return 1
		}
	}
	fmt.Printf("导入完成（幂等：重复执行为 upsert，结果一致）\n")
	return 0
}

// migrateImportTable 单表 upsert 导入（整表一个事务，失败整体回滚）。
func migrateImportTable(dst *sqlutil.DB, spec migrateTableSpec, td migrateTableDump) (int, error) {
	if len(td.Columns) == 0 {
		return 0, nil
	}
	cols, err := migrateColumns(dst, spec.name)
	if err != nil {
		return 0, err
	}
	// 以目标库列为准：dump 列与目标列取交集，缺列 → fail-closed（schema 漂移）。
	idx := make([]int, 0, len(cols))
	for _, c := range cols {
		pos := -1
		for i, dc := range td.Columns {
			if dc == c {
				pos = i
				break
			}
		}
		if pos < 0 {
			return 0, fmt.Errorf("目标列 %s.%s 在 dump 中缺失（schema 漂移，拒绝导入）", spec.name, c)
		}
		idx = append(idx, pos)
	}
	// 主键列不进入 SET（复合主键的每一列都不进）；仅主键列的表用 DO NOTHING（幂等）。
	pkCols := spec.pkColumns()
	pkSet := make(map[string]bool, len(pkCols))
	for _, c := range pkCols {
		pkSet[c] = true
	}
	var sets []string
	for _, c := range cols {
		if pkSet[c] {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = excluded.%s", c, c))
	}
	conflict := "DO NOTHING"
	if len(sets) > 0 {
		conflict = "DO UPDATE SET " + strings.Join(sets, ", ")
	}
	q := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) %s`,
		spec.name, strings.Join(cols, ", "),
		strings.TrimRight(strings.Repeat("?, ", len(cols)), ", "),
		strings.Join(pkCols, ", "), conflict)

	tx, err := dst.Begin()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, row := range td.Rows {
		args := make([]any, 0, len(idx))
		for _, pos := range idx {
			args = append(args, row[pos])
		}
		if _, err := tx.Exec(q, args...); err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("写行失败（表 %s）: %w", spec.name, err)
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// migrateFixSequences PG 侧 BIGSERIAL 序列回填（否则后续插入主键冲突）。
func migrateFixSequences(dst *sqlutil.DB, specs []migrateTableSpec) error {
	if !dst.Dialect().IsPostgres() {
		return nil // sqlite 无独立序列
	}
	for _, spec := range specs {
		if spec.serial == "" || spec.skip != "" {
			continue
		}
		// setval 到当前最大 id（无行时置 1）；pg_get_serial_sequence 取序列名。
		if _, err := dst.Exec(`SELECT setval(pg_get_serial_sequence(?, ?), GREATEST(COALESCE((SELECT MAX(`+spec.serial+`) FROM `+spec.name+`), 0), 1))`,
			spec.name, spec.serial); err != nil {
			return fmt.Errorf("回填 %s.%s 序列失败: %w", spec.name, spec.serial, err)
		}
		fmt.Printf("%-24s 序列已回填\n", spec.name)
	}
	return nil
}

// migrateRunVerify 逐表比对源/目标行数与校验和（不通过 → 退出码 1，禁止切换）。
func migrateRunVerify(opt *migrateOptions, specs []migrateTableSpec) int {
	sources, err := migrateOpenSources(opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}
	defer sources.close()
	dst, err := migrateOpenTarget(opt.to, opt.toDriver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}
	defer dst.Close()
	explicit := len(opt.tables) > 0
	diff := 0
	for _, spec := range specs {
		src := sources.forSpec(spec)
		if src == nil {
			if explicit {
				fmt.Fprintf(os.Stderr, "migrate: 集群注册表源不可用（-tables 显式指定，fail-closed）\n")
				return 1
			}
			fmt.Printf("%-24s 集群注册表源不可用（跳过对账）\n", spec.name)
			continue
		}
		if exists, err := migrateTableExists(src, spec.name); err == nil && !exists {
			fmt.Printf("%-24s 源库无此表（跳过对账）\n", spec.name)
			continue
		}
		sd, err := migrateReadTable(src, spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate: 读源表 %s 失败: %v\n", spec.name, err)
			return 1
		}
		if spec.skip != "" {
			fmt.Printf("%-24s 跳过对账（%s）\n", spec.name, spec.skip)
			continue
		}
		if exists, err := migrateTableExists(dst, spec.name); err == nil && !exists {
			fmt.Printf("%-24s 目标缺表（须先建表/导入）\n", spec.name)
			diff++
			continue
		}
		td, err := migrateReadTable(dst, spec)
		if err != nil {
			fmt.Printf("%-24s 目标读取失败: %v\n", spec.name, err)
			diff++
			continue
		}
		if sd.Count == td.Count && sd.Checksum == td.Checksum {
			fmt.Printf("%-24s OK rows=%d\n", spec.name, sd.Count)
			continue
		}
		fmt.Printf("%-24s 不一致：源 rows=%d/%s 目标 rows=%d/%s\n",
			spec.name, sd.Count, shortSum(sd.Checksum), td.Count, shortSum(td.Checksum))
		diff++
	}
	if diff > 0 {
		fmt.Printf("\n对账未通过（%d 张表不一致）——**不得切换**，请先 import -apply 后重验\n", diff)
		return 1
	}
	fmt.Print("\n对账通过：源与目标行数与内容摘要一致\n")
	return 0
}

// migrateRunRollback 回滚：默认打印 SOP；-purge 时清除目标库**本次导入的行**。
func migrateRunRollback(opt *migrateOptions, specs []migrateTableSpec) int {
	fmt.Print("回滚 SOP：\n" +
		"  1) 先把 SECURITY_STORE_PG_DSN / 租户库方言切回 sqlite（进程内实现），滚动重启；\n" +
		"  2) sqlite 源库全程只读未被改写，切回即可恢复切换前行为；\n" +
		"  3) 目标共享库数据保留待对账（默认不清）；确需清除已导入行时加 -purge。\n")
	if !opt.purge {
		return 0
	}
	dst, err := migrateOpenTarget(opt.to, opt.toDriver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 2
	}
	defer dst.Close()
	// 精确清除：按 dump 中的主键删除本次导入的行，**不动目标库既有数据**
	// （早前实现是清空整表，会误删目标库已有数据——与文档口径不符，已修正）。
	dump, err := migrateLoadDump(opt.out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: 清除失败: %v\n", err)
		return 2
	}
	// 自引用表（tenant_statements.supersedes_id）按倒序删，避免自引用冲突。
	order := make([]migrateTableSpec, len(specs))
	copy(order, specs)
	sort.SliceStable(order, func(i, j int) bool {
		return migrateDeleteRank(order[i].name) > migrateDeleteRank(order[j].name)
	})
	total := int64(0)
	for _, spec := range order {
		if spec.skip != "" {
			continue
		}
		td, ok := dump.Tables[spec.name]
		if !ok || td.Skipped != "" {
			fmt.Printf("%-24s 未导入，跳过\n", spec.name)
			continue
		}
		n, err := migratePurgeTable(dst, spec, td)
		if err != nil {
			fmt.Printf("%-24s 清除失败: %v\n", spec.name, err)
			continue
		}
		total += n
		fmt.Printf("%-24s 已清除 rows=%d\n", spec.name, n)
	}
	fmt.Printf("目标库已清除本次导入的行（共 %d 行；源 sqlite 未受影响）\n", total)
	return 0
}

// migrateLoadDump 读取并校验 dump 文件（版本不符 → fail-closed）。
func migrateLoadDump(path string) (migrateDump, error) {
	var dump migrateDump
	raw, err := os.ReadFile(path)
	if err != nil {
		return dump, fmt.Errorf("读 dump 失败（-purge 需 dump 才能精确清除已导入行）: %w", err)
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return dump, fmt.Errorf("dump 解析失败（文件损坏？）: %w", err)
	}
	if dump.Version != migrateDumpVersion {
		return dump, fmt.Errorf("dump 版本 %d 不受支持（当前 %d）", dump.Version, migrateDumpVersion)
	}
	return dump, nil
}

// migratePurgeTable 按 dump 主键精确删除本次导入的行（分批 IN，避免超长语句）。
func migratePurgeTable(dst *sqlutil.DB, spec migrateTableSpec, td migrateTableDump) (int64, error) {
	if len(td.Rows) == 0 {
		return 0, nil
	}
	pkCols := spec.pkColumns()
	// dump 中的主键列下标（复合主键逐列定位）。
	pkIdx := make([]int, 0, len(pkCols))
	for _, c := range pkCols {
		pos := -1
		for i, dc := range td.Columns {
			if dc == c {
				pos = i
				break
			}
		}
		if pos < 0 {
			return 0, fmt.Errorf("dump 中找不到主键列 %s", c)
		}
		pkIdx = append(pkIdx, pos)
	}
	const batch = 500
	total := int64(0)
	for start := 0; start < len(td.Rows); start += batch {
		end := start + batch
		if end > len(td.Rows) {
			end = len(td.Rows)
		}
		args := make([]any, 0, (end-start)*len(pkIdx))
		holders := make([]string, 0, end-start)
		for _, row := range td.Rows[start:end] {
			rowHolders := make([]string, 0, len(pkIdx))
			for _, pos := range pkIdx {
				if pos >= len(row) {
					return total, fmt.Errorf("dump 行长度异常（主键列越界）")
				}
				args = append(args, row[pos])
				rowHolders = append(rowHolders, "?")
			}
			holders = append(holders, "("+strings.Join(rowHolders, ", ")+")")
		}
		var q string
		if len(pkCols) == 1 {
			// 单列主键：IN 列表（与既有实现一致，避开行值语法的方言差异）。
			q = fmt.Sprintf(`DELETE FROM %s WHERE %s IN (%s)`, spec.name, pkCols[0], strings.Join(holders, ", "))
		} else {
			// 复合主键：行值 IN（sqlite ≥3.15 / PG 均支持）。
			q = fmt.Sprintf(`DELETE FROM %s WHERE (%s) IN (%s)`, spec.name,
				strings.Join(pkCols, ", "), strings.Join(holders, ", "))
		}
		res, err := dst.Exec(q, args...)
		if err != nil {
			return total, fmt.Errorf("按主键清除失败: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// migrateDeleteRank 删除次序（大 = 先删）：子表先于父表，自引用表优先。
func migrateDeleteRank(table string) int {
	switch table {
	case "tenant_statements":
		return 5
	case "tenant_dispatch_state", "tenant_provisionings", "api_keys", "policy_overlays",
		"model_configs", "subscription_requests", "mail_action_tokens":
		return 4
	case "tenant_users":
		return 3
	case "tenants":
		return 1
	default:
		return 2 // 安全计数器表（无 FK）
	}
}

// shortSum 校验和前 8 位（日志/表格展示用）。
func shortSum(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
