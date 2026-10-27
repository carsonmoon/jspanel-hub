//! SQLite storage. A single writer connection behind a mutex: at a handful of
//! nodes reporting every few seconds, every statement here is sub-millisecond.
// ponytail: single global connection; move to a read pool if the dashboard ever
// blocks behind ingest.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Local, NaiveDate, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

pub struct ConnLogFilter {
    pub server_id: Option<i64>,
    /// 来源筛选：None=全部，Some("__none__")=未认领（自用），Some(名字)=该客户。
    pub user: Option<String>,
    /// 节点筛选：入站 tag（如 "in-24443"）。
    pub node: Option<String>,
    pub q: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub page: u32,
}

const CONN_LOG_PAGE: i64 = 50;

fn conn_log_where(f: &ConnLogFilter) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conds = vec!["1=1".to_string()];
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(sv) = f.server_id {
        conds.push(format!("server_id = ?{}", params.len() + 1));
        params.push(Box::new(sv));
    }
    match &f.user {
        Some(u) if u == "__none__" => conds.push("sub_user_id IS NULL".to_string()),
        Some(u) => {
            conds.push(format!("user = ?{}", params.len() + 1));
            params.push(Box::new(u.clone()));
        }
        None => {}
    }
    if let Some(tag) = &f.node {
        conds.push(format!("inbound = ?{}", params.len() + 1));
        params.push(Box::new(tag.clone()));
    }
    if let Some(q) = &f.q {
        conds.push(format!(
            "(host LIKE ?{} OR source LIKE ?{} OR user LIKE ?{})",
            params.len() + 1,
            params.len() + 2,
            params.len() + 2
        ));
        let like = format!("%{}%", q.replace(['%', '_'], ""));
        params.push(Box::new(like.clone()));
        params.push(Box::new(like));
    }
    if let Some(s) = f.since {
        conds.push(format!("ts_last >= ?{}", params.len() + 1));
        params.push(Box::new(s));
    }
    if let Some(u) = f.until {
        conds.push(format!("ts_last <= ?{}", params.len() + 1));
        params.push(Box::new(u));
    }
    (format!("WHERE {}", conds.join(" AND ")), params)
}

pub struct Db(Mutex<Connection>);

thread_local! {
    /// 本线程当前存活的 conn 守卫所属 Db 实例地址栈。Db 的 Mutex 非重入，
    /// 同一实例同线程重入是必然死锁，已两次进生产（strip_server_from_mirrors、
    /// take_mcp_code 整站冻结）。跨实例嵌套持锁合法（不同的锁），不误报。
    static CONN_HELD: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// conn 守卫：Drop 从线程本地栈移除本实例（含 dev 构建 panic 展开的兜底；
/// 守卫借用 &Db，地址不可能在守卫存活期间被复用）。Deref 到 Connection，
/// 调用点用法与原 MutexGuard 一致。
struct ConnGuard<'a> {
    guard: std::sync::MutexGuard<'a, Connection>,
    db: usize,
}

impl std::ops::Deref for ConnGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.guard
    }
}

impl std::ops::DerefMut for ConnGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.guard
    }
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        CONN_HELD.with(|held| held.borrow_mut().retain(|&p| p != self.db));
    }
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
-- 8 MiB of page cache. The whole working set of a few hundred nodes fits, so
-- the read paths stop going back to the filesystem.
PRAGMA cache_size = -8192;
-- Without these the WAL grows to whatever the busiest minute needed and never
-- gives the space back: a hub is a long-running process on a small VPS.
PRAGMA wal_autocheckpoint = 256;
PRAGMA journal_size_limit = 1048576;

CREATE TABLE IF NOT EXISTS setting (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node (
  id            INTEGER PRIMARY KEY,
  name          TEXT    NOT NULL,
  -- The agent's credential, in the clear: the panel shows a node's install
  -- command whenever it is asked, so it has to be able to read it back.
  token         TEXT    NOT NULL UNIQUE,
  sort          INTEGER NOT NULL DEFAULT 0,
  public        INTEGER NOT NULL DEFAULT 1,
  price         REAL    NOT NULL DEFAULT 0,
  currency      TEXT    NOT NULL DEFAULT 'USD',
  billing_cycle TEXT    NOT NULL DEFAULT 'monthly',
  expires_at    TEXT,
  remark        TEXT    NOT NULL DEFAULT '',
  traffic_limit INTEGER NOT NULL DEFAULT 0,
  traffic_mode  TEXT    NOT NULL DEFAULT 'sum',
  traffic_reset_day INTEGER NOT NULL DEFAULT 1,
  hostname TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '',
  kernel   TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '',
  virt     TEXT NOT NULL DEFAULT '', cpu_name TEXT NOT NULL DEFAULT '',
  cpu_cores INTEGER NOT NULL DEFAULT 0, mem_total INTEGER NOT NULL DEFAULT 0,
  swap_total INTEGER NOT NULL DEFAULT 0, disk_total INTEGER NOT NULL DEFAULT 0,
  agent_version TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
  ipv4 TEXT NOT NULL DEFAULT '', ipv6 TEXT NOT NULL DEFAULT '',
  -- ISO 3166-1 alpha-2, looked up from `country_ip` once per address. Empty
  -- until the lookup answers, and empty is what a node whose country nobody
  -- could tell stays: the public page just leaves the badge off.
  country TEXT NOT NULL DEFAULT '',
  -- The address `country` belongs to: a public interface address the agent
  -- reported, else `ip`. Empty when neither is public.
  country_ip TEXT NOT NULL DEFAULT '',
  -- The last answered pair `country_ip` / `country` before the current one;
  -- an address never answered does not displace it. A hello taken before
  -- every interface is up picks the other family, and the next one returns;
  -- the address returned to takes its answer back from here instead of
  -- waiting out the hourly lookup limit the detour spent.
  -- One pair suffices: a machine's sources are its v4, or the exit in front of
  -- it, and its v6.
  country_prev_ip TEXT NOT NULL DEFAULT '',
  country_prev TEXT NOT NULL DEFAULT '',
  -- Set in the panel. When not empty it is the country shown, in place of the
  -- looked-up one, which goes on updating underneath.
  country_pin TEXT NOT NULL DEFAULT '',
  -- Set in the panel and shown on the status page, where a theme may divide the
  -- node list by it. Empty is ungrouped. Not `group`, a reserved word.
  group_name TEXT NOT NULL DEFAULT '',
  -- Set in the panel, each replacing the address shown for its family. Empty
  -- means automatic. Panel only, like the reported addresses.
  ipv4_pin TEXT NOT NULL DEFAULT '', ipv6_pin TEXT NOT NULL DEFAULT '',
  -- Survives the disconnection it describes, unlike the in-memory live entry:
  -- an offline node's page is exactly where "since when" is worth reading.
  last_seen INTEGER NOT NULL DEFAULT 0,
  -- Opt-in, as the operator decides which machines are worth an alert.
  notify INTEGER NOT NULL DEFAULT 0,
  -- `last_seen` as of the offline alert, zero while none is outstanding. Stored
  -- rather than held in memory so that a hub restart neither repeats the alert
  -- nor loses the recovery that pairs with it.
  down_since INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

-- Monotonic byte counters that survive both agent reboots and hub restarts.
CREATE TABLE IF NOT EXISTS traffic (
  node_id  INTEGER PRIMARY KEY REFERENCES node(id) ON DELETE CASCADE,
  boot_id  TEXT    NOT NULL DEFAULT '',
  last_rx  INTEGER NOT NULL DEFAULT 0,
  last_tx  INTEGER NOT NULL DEFAULT 0,
  total_rx INTEGER NOT NULL DEFAULT 0,
  total_tx INTEGER NOT NULL DEFAULT 0,
  month_rx INTEGER NOT NULL DEFAULT 0,
  month_tx INTEGER NOT NULL DEFAULT 0,
  month_start TEXT NOT NULL DEFAULT '',
  day_rx INTEGER NOT NULL DEFAULT 0,
  day_tx INTEGER NOT NULL DEFAULT 0,
  day_start TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS metric (
  node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  ts      INTEGER NOT NULL,
  cpu REAL NOT NULL,
  mem_used INTEGER NOT NULL, swap_used INTEGER NOT NULL, disk_used INTEGER NOT NULL,
  net_rx INTEGER NOT NULL, net_tx INTEGER NOT NULL,
  tcp INTEGER NOT NULL, udp INTEGER NOT NULL, procs INTEGER NOT NULL,
  net_rx_max INTEGER NOT NULL DEFAULT 0, net_tx_max INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ping_task (
  id       INTEGER PRIMARY KEY,
  name     TEXT    NOT NULL,
  target   TEXT    NOT NULL,
  interval INTEGER NOT NULL DEFAULT 60,
  auto_join INTEGER NOT NULL DEFAULT 0,
  sort     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ping_node (
  task_id INTEGER NOT NULL REFERENCES ping_task(id) ON DELETE CASCADE,
  node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  PRIMARY KEY (task_id, node_id)
);

-- Key order follows the only query there is: one node, one time window,
-- every probe. With task_id ahead of ts SQLite can seek to the node and no
-- further, then scans every record it ever kept -- see the migration in open().
CREATE TABLE IF NOT EXISTS ping_record (
  node_id INTEGER NOT NULL, task_id INTEGER NOT NULL,
  ts INTEGER NOT NULL, latency INTEGER NOT NULL,
  PRIMARY KEY (node_id, ts, task_id)
) WITHOUT ROWID;

-- 延迟探测告警状态（三期）：key = "{node_id}:{task_id}:{kind}"，kind =
-- loss / latency。raised_at 起报、recovered_at 恢复（NULL=进行中，概览的
-- 监测告警概览卡读它）；confirmed/normal_streak 是状态机的连续计数，
-- baseline 缓存最近一次学到的基线，跨重启不丢。
CREATE TABLE IF NOT EXISTS ping_alert (
  key          TEXT PRIMARY KEY,
  node_id      INTEGER NOT NULL,
  task_id      INTEGER NOT NULL,
  kind         TEXT NOT NULL,
  raised_at    INTEGER NOT NULL,
  confirmed    INTEGER NOT NULL DEFAULT 0,
  normal_streak INTEGER NOT NULL DEFAULT 0,
  baseline     INTEGER,
  detail       TEXT NOT NULL DEFAULT '',
  checked_at   INTEGER NOT NULL DEFAULT 0,
  recovered_at INTEGER
);

-- 回程线路探测（四期）：任务指派到监控节点，hub 调度 agent 的 ICMP
-- traceroute，识别每跳归属线路，链路主线路连续两次与基线不同即记
-- 「线路变化」事件（四期只做切线事件，恢复即基线跟随）。
CREATE TABLE IF NOT EXISTS route_task (
  id         INTEGER PRIMARY KEY,
  name       TEXT    NOT NULL,
  target     TEXT    NOT NULL,
  interval   INTEGER NOT NULL DEFAULT 600,
  enabled    INTEGER NOT NULL DEFAULT 1,
  sort       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS route_task_node (
  task_id INTEGER NOT NULL REFERENCES route_task(id) ON DELETE CASCADE,
  node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  PRIMARY KEY (task_id, node_id)
);
CREATE TABLE IF NOT EXISTS route_status (
  task_id   INTEGER NOT NULL,
  node_id   INTEGER NOT NULL,
  hops      TEXT NOT NULL DEFAULT '[]',  -- [{ttl, ip, line}]
  line      TEXT NOT NULL DEFAULT '',    -- 最近一次识别的链路主线路
  baseline  TEXT NOT NULL DEFAULT '',    -- 基线线路（学习期建立）
  probes    INTEGER NOT NULL DEFAULT 0,  -- 已探测次数（学习期判定）
  streak    INTEGER NOT NULL DEFAULT 0,  -- 当前线路与基线不同的连续次数
  probed_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (task_id, node_id)
);
CREATE TABLE IF NOT EXISTS route_event (
  id        INTEGER PRIMARY KEY,
  task_id   INTEGER NOT NULL,
  node_id   INTEGER NOT NULL,
  from_line TEXT NOT NULL,
  to_line   TEXT NOT NULL,
  at        INTEGER NOT NULL
);


CREATE TABLE IF NOT EXISTS session (
  token_hash TEXT    PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

-- The four proxy tables (proxy_node / proxy_secret / proxy_user / sub_user)
-- are NOT here: they arrive with migrate_to_10, inside the upgrade
-- transaction, so a failed upgrade leaves no trace of them. Fresh files run
-- the full migration history for the same reason -- see open().
"#;

/// Schema revision this build expects, stamped into `PRAGMA user_version`.
/// Increment it and add a `migrate_to_N` when the schema changes under a
/// database already in service. Every migration must be:
///
/// - Additive: a new column carries a default, and no column an earlier build
///   reads is renamed or dropped. install-hub.sh rolls a hub that fails to start
///   back to the previous binary, which then runs on the migrated file.
/// - Safe to run twice: an earlier build stamps its own, lower version into a
///   newer file, and the next upgrade runs the migration again.
///
/// A new column goes into `SCHEMA` as well, for fresh files, but an index on it
/// cannot: `open` runs `SCHEMA` before migrating, and on an older file the
/// column is not there yet. `an_upgraded_release_matches_a_fresh_database`
/// holds every migration to these rules, starting from v1.0.0's schema.
/// Bumped to 11 for Shadowsocks（proxy_node.method）and inline self-signed
/// certificates（proxy_secret.cert_pem / key_pem）. `migrate_to_11` carries the
/// columns to v10 files; fresh files get them straight from `migrate_to_10`.
/// Bumped to 12 for per-node chained egress fields（M2.5，同样新旧两路）.
/// Bumped to 13 for multi-machine（M3）：proxy_node.server_id 与审计表 agent_jobs.
/// Bumped to 14 for M4：traffic_samples.server_id（节点流量按服务器记账）.
/// Bumped to 15 for M5：relay_rules（Realm 中转规则）.
/// Bumped to 16 for VLESS flow selection.
/// Bumped to 17 to fold upstream v1.3.1's metric peak columns（net_rx_max /
/// net_tx_max）in：上游同样占用了 10 号，这里作为我们迁移链的新末步，已有
/// v16 部署升级时补列，新库从头跑全链同样到达。
/// Bumped to 19 for M7：sub_user 的流量配额列（额度、重置方式、当期上行/
/// 下行已用、当期起点）。用量直接累积在客户行上而不是采样表——采样按保留
/// 期清理会让一次性总量包失忆，而配额判定只读本行，不必每次聚合大表；上
/// 下行分开记，订阅响应的 subscription-userinfo 要分开回传。
/// Bumped to 21（跳过 20：M10 的 20 号迁移已随回退删除，但存量库——至少
/// 服务器——已 stamped 20，新迁移必须大于 20 才能在那些库上执行）：
/// traffic_samples 加 ts 索引。该表记录每 30s 量级的流量采样，是概览走势、
/// 节点/用户排行与配额记账的数据源，按时间窗查询是它的主要访问模式。
/// Bumped to 22 for M14：connection_log——逐连接的客户端 IP / 访问目标 /
/// 归属客户日志（sing-box api 连接事件流落库），含 server_id+conn_id 主键
/// 与 ts / 客户 两级索引。
/// Bumped to 23 for 概览客户排行按时间窗（24h/7d/30d）联动：sub_usage_hourly
/// ——每客户每小时的用户量汇总。当期累计（sub_user.quota_used_*）没有窗口
/// 维度，而现查 connection_log 又依赖记录开关与保留期（默认 7 天）。建表时
/// 从 connection_log 一次性回填，之后由 bump_sub_usage 在记账事务里同步增量。
/// Bumped to 24 for 隧道规则模型 v2（对标 realm-xwPF）：relay_rules 加列
/// （协议选择/备注/负载均衡/加密隧道两端/高级绑定），relay_targets 落地
/// 目标子表（多落地 + 健康状态），存量 target 逐条回填为第一目标。
/// Bumped to 25（第二次使用）for 订阅转换 v2（严格按 miaomiaowu 架构重做，
/// 上一版 pool_* 实现已随 2d9e5b6 回退且服务器残留表已清理）：五张 sub_*
/// 表——sub_nodes（节点池，双形态：分享链接 raw_link 或 Clash 原生字段
/// clash_config JSON，标签制组织，source_url 关联外部订阅源支持同步）、
/// sub_sources（外部订阅源实体：UA/自动同步间隔/上游流量）、sub_templates
/// （完整 Clash 配置模板，内容入库随备份走）、sub_rule_snippets（命名规则
/// 片段：整段 YAML，prepend/append 合并）、sub_profiles（生成的订阅文件：
/// 模板绑定+标签勾选+片段勾选+有效期，token 守卫对外）。
/// Bumped to 26（第二次使用）for 订阅页 v2.1：sub_profiles 加 group_overrides
/// （组→有序节点 id 的覆盖表，可视化拖拽分组；未覆盖的组仍走模板占位符）、
/// sub_templates seed 三份规则模式内置模板（极简/均衡/完整，MetaCubeX mrs
/// 规则集目录，代码按类别表生成）。
/// Bumped to 27（第二次使用）for 规则模式 v3：sub_profiles 加
/// selected_categories（勾选的分流类别 key 数组，非空 = 按类别动态生成
/// 模式，template_name 可为空）。
/// Bumped to 28（第二次使用）for 订阅文件节点勾选：sub_profiles 加
/// selected_nodes（勾选的节点 id 数组，非空 = 只包含这些节点）。
const SCHEMA_VERSION: i64 = 53;

/// Adds a column older databases lack. A duplicate column indicates the
/// migration has already run; every other error must propagate.
fn add_column(conn: &Connection, table: &str, column: &str) -> Result<()> {
    match conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column}"), []) {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// True when `table`'s stored DDL contains `needle`, which is how a migration
/// determines the shape of the database it inherited.
fn schema_mentions(conn: &Connection, table: &str, needle: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name=?1 AND sql LIKE ?2",
        params![table, format!("%{needle}%")],
        |r| r.get::<_, i64>(0),
    )? > 0)
}

/// One table's column names. `table` is always a [`TABLES`] entry rather than
/// caller-supplied, which is why it can be formatted into the pragma.
fn columns_of(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    Ok(names.collect::<Result<_, _>>()?)
}

/// Everything accumulated before a version was recorded. Runs once, on a
/// database predating the stamp.
fn migrate_to_1(conn: &Connection) -> Result<()> {
    for column in [
        "day_rx INTEGER NOT NULL DEFAULT 0",
        "day_tx INTEGER NOT NULL DEFAULT 0",
        "day_start TEXT NOT NULL DEFAULT ''",
    ] {
        add_column(conn, "traffic", column)?;
    }
    for column in [
        "ipv4 TEXT NOT NULL DEFAULT ''",
        "ipv6 TEXT NOT NULL DEFAULT ''",
        "last_seen INTEGER NOT NULL DEFAULT 0",
    ] {
        add_column(conn, "node", column)?;
    }
    // The column held a sha256 of the token and now holds the token itself.
    // Databases predating the change retain digests no agent can present, so
    // those nodes require a new token issued from the panel.
    if schema_mentions(conn, "node", "token_hash")? {
        conn.execute("ALTER TABLE node RENAME COLUMN token_hash TO token", [])?;
        info!("renamed node.token_hash to node.token; existing nodes need a fresh token");
    }
    // Reordering a key requires rebuilding the table; CREATE TABLE IF NOT EXISTS
    // leaves an existing one untouched. The old order placed task_id between the
    // node and the timestamp, so the chart query scanned a node's entire history
    // to answer for one hour of it: 42 ms against 0.8 ms at a month of
    // retention.
    if schema_mentions(conn, "ping_record", "(node_id, task_id, ts)")? {
        conn.execute_batch(
            "CREATE TABLE ping_record_rekeyed (
               node_id INTEGER NOT NULL, task_id INTEGER NOT NULL,
               ts INTEGER NOT NULL, latency INTEGER NOT NULL,
               PRIMARY KEY (node_id, ts, task_id)
             ) WITHOUT ROWID;
             INSERT INTO ping_record_rekeyed SELECT * FROM ping_record;
             DROP TABLE ping_record;
             ALTER TABLE ping_record_rekeyed RENAME TO ping_record;",
        )?;
        info!("rebuilt ping_record on a key the latency chart can seek");
    }
    Ok(())
}

/// `metric.load1` was written on every history row and read by nothing: the card
/// draws the live `load` array from the report, and no chart draws load from
/// history. Dropping it recovers 21% of what the five unread columns cost, and
/// it is the only one the hub can lose without also losing a figure the UI
/// displays.
///
/// The column is `NOT NULL` with no default, so this migration is mandatory:
/// without it every metric insert this build makes violates the constraint.
fn migrate_to_2(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "metric", "load1")? {
        conn.execute("ALTER TABLE metric DROP COLUMN load1", [])?;
        info!("dropped metric.load1; nothing read it");
    }
    Ok(())
}

fn migrate_to_3(conn: &Connection) -> Result<()> {
    add_column(conn, "node", "country TEXT NOT NULL DEFAULT ''")
}

fn migrate_to_4(conn: &Connection) -> Result<()> {
    add_column(conn, "node", "notify INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "node", "down_since INTEGER NOT NULL DEFAULT 0")
}

/// Every country stored until now was looked up from `ip`. Recording that
/// keeps the badge of a node whose lookup address is still `ip`, and has a node
/// whose public interface address now takes precedence looked up again at its
/// next hello. The columns set by hand start empty: automatic.
fn migrate_to_5(conn: &Connection) -> Result<()> {
    add_column(conn, "node", "country_ip TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "node", "country_pin TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "node", "ipv4_pin TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "node", "ipv6_pin TEXT NOT NULL DEFAULT ''")?;
    conn.execute("UPDATE node SET country_ip = ip WHERE country != ''", [])?;
    Ok(())
}

fn migrate_to_6(conn: &Connection) -> Result<()> {
    add_column(conn, "ping_task", "auto_join INTEGER NOT NULL DEFAULT 0")
}

fn migrate_to_7(conn: &Connection) -> Result<()> {
    add_column(conn, "node", "group_name TEXT NOT NULL DEFAULT ''")
}

fn migrate_to_8(conn: &Connection) -> Result<()> {
    add_column(conn, "node", "country_prev_ip TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "node", "country_prev TEXT NOT NULL DEFAULT ''")
}

/// Every existing probe ties at 0, so `ORDER BY sort, id` keeps the id order an
/// upgraded database listed them in.
fn migrate_to_9(conn: &Connection) -> Result<()> {
    add_column(conn, "ping_task", "sort INTEGER NOT NULL DEFAULT 0")
}

/// The proxy module's tables (设计文档 7). Created here rather than in
/// `SCHEMA` so the creation lives inside the upgrade transaction: a failed
/// upgrade must leave no step behind, and a fresh file runs this history too.
fn migrate_to_10(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS proxy_node (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          -- vless-reality / hysteria2 / shadowsocks / anytls / socks / http
          protocol TEXT NOT NULL,
          -- 业务端口，端口池内分配；同服务器唯一（M3 起按 server_id 隔离）
          listen_port INTEGER NOT NULL,
          sni TEXT NOT NULL DEFAULT '',
          -- VLESS Reality flow: xtls-rprx-vision or empty.
          flow TEXT NOT NULL DEFAULT 'xtls-rprx-vision',
          -- Shadowsocks 的加密方法；其余协议为空
          method TEXT NOT NULL DEFAULT '',
          -- 只影响订阅与链接，不触发核心重启（设计文档 6.3）
          enabled INTEGER NOT NULL DEFAULT 1,
          remark TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL,
          -- 节点所在服务器：0 = hub 本机，其余为 node 表主键（M3）
          server_id INTEGER NOT NULL DEFAULT 0,
          -- 链式出口（M2.5）：空 = 直接出网；socks5 / http = 流量先交给上游代理
          egress_type TEXT NOT NULL DEFAULT '',
          egress_host TEXT NOT NULL DEFAULT '',
          egress_port INTEGER NOT NULL DEFAULT 0,
          egress_username TEXT NOT NULL DEFAULT '',
          egress_password TEXT NOT NULL DEFAULT '',
          -- 表约束必须写在它引用的列之后（SQLite 的解析要求）
          UNIQUE(listen_port, server_id)
        );

        CREATE TABLE IF NOT EXISTS proxy_secret (
          node_id INTEGER PRIMARY KEY REFERENCES proxy_node(id) ON DELETE CASCADE,
          -- reality / selfsign / none
          tls_mode TEXT NOT NULL DEFAULT '',
          private_key TEXT NOT NULL DEFAULT '',
          public_key TEXT NOT NULL DEFAULT '',
          short_id TEXT NOT NULL DEFAULT '',
          -- 自签证书的 PEM（hysteria2 / anytls 的 selfsign 模式），内联进配置
          cert_pem TEXT NOT NULL DEFAULT '',
          key_pem TEXT NOT NULL DEFAULT '',
          -- Shadowsocks-2022 多用户的服务器 PSK（顶层 password）
          psk TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS proxy_user (
          id INTEGER PRIMARY KEY,
          node_id INTEGER NOT NULL REFERENCES proxy_node(id) ON DELETE CASCADE,
          -- 兼作入站里的用户标识
          name TEXT NOT NULL,
          -- uuid / password / ss 密钥，面板可读回以便展示链接
          credential TEXT NOT NULL,
          sub_user_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS sub_user (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          token TEXT NOT NULL UNIQUE,
          enabled INTEGER NOT NULL DEFAULT 1,
          expires_at TEXT,
          remark TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

/// The columns M2 added to the proxy tables: Shadowsocks' cipher and server
/// PSK, plus the inline self-signed certificate pair. Fresh files already
/// hold them in `migrate_to_10`'s DDL, so `add_column` no-ops there.
fn migrate_to_11(conn: &Connection) -> Result<()> {
    add_column(conn, "proxy_node", "method TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_secret", "cert_pem TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_secret", "key_pem TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_secret", "psk TEXT NOT NULL DEFAULT ''")
}

/// Per-node chained egress（M2.5）：socks5 / http 上游代理。空 type = 直连。
fn migrate_to_12(conn: &Connection) -> Result<()> {
    add_column(conn, "proxy_node", "egress_type TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_node", "egress_host TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_node", "egress_port INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "proxy_node", "egress_username TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_node", "egress_password TEXT NOT NULL DEFAULT ''")
}

/// 多机管理（M3）：节点归属服务器（0 = hub 本机），agent_jobs 留下每一次
/// 下发的痕迹（设计文档 5.6 收敛为哈希对账驱动，此表作审计）。
fn migrate_to_13(conn: &Connection) -> Result<()> {
    add_column(conn, "proxy_node", "server_id INTEGER NOT NULL DEFAULT 0")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS agent_jobs (
          id INTEGER PRIMARY KEY,
          server_id INTEGER NOT NULL,
          method TEXT NOT NULL,
          state TEXT NOT NULL,
          detail TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_proxy_node_server ON proxy_node(server_id);",
    )?;
    Ok(())
}

/// M5：Realm 中转规则。listen_port 可以是单端口或端口段（"20000-20100"），
/// target 是落地地址（"host:port" 或 "host:min-max"，段对段）。
/// M6：origin_link 保存导入式规则的原始节点分享链接，中转分享链接由它改写。
fn migrate_to_15(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS relay_rules (
          id INTEGER PRIMARY KEY,
          server_id INTEGER NOT NULL DEFAULT 0,
          name TEXT NOT NULL,
          listen_port TEXT NOT NULL,
          target TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          origin_link TEXT NOT NULL DEFAULT ''
        );",
    )?;
    Ok(())
}

/// M6：导入式中转的原始链接列，v17 及更早的库幂等补列。
fn migrate_to_18(conn: &Connection) -> Result<()> {
    add_column(conn, "relay_rules", "origin_link TEXT NOT NULL DEFAULT ''")
}

/// M7：客户配额列。quota_bytes 0 = 不限；quota_reset '' = 一次性总量包、
/// 'monthly' = 自然月重置（本地时区，与流量日界一致）；quota_used_up/down
/// 是当期已累积的用户级用量，由记账链路增量维护；quota_period_start 标明
/// 它从哪个自然月起算，跨月首次记账时清零。
fn migrate_to_19(conn: &Connection) -> Result<()> {
    add_column(conn, "sub_user", "quota_bytes INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "sub_user", "quota_reset TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "sub_user", "quota_used_up INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "sub_user", "quota_used_down INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "sub_user", "quota_period_start INTEGER NOT NULL DEFAULT 0")
}

/// M11（沿用 M10 空出的 20 号之后为 21）：traffic_samples 的 ts 索引——
/// 时间窗聚合（概览走势/排行）与保留期清理都按 ts 扫描。
fn migrate_to_21(conn: &Connection) -> Result<()> {
    // 表本身在 v14 才出现：更老的库先没有这张表，索引随表一起在 SCHEMA 里建。
    if schema_mentions(conn, "traffic_samples", "node_tag")? {
        conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_traffic_samples_ts ON traffic_samples(ts)")?;
    }
    Ok(())
}

/// M14：连接日志（逐连接的客户端 IP / 访问目标 / 归属客户）。主键含
/// conn_id：同一连接的快照行随生命周期 upsert，CLOSED 定稿。
fn migrate_to_22(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS connection_log (
           conn_id TEXT NOT NULL,
           server_id INTEGER NOT NULL,
           ts_first INTEGER NOT NULL,
           ts_last INTEGER NOT NULL,
           user TEXT NOT NULL DEFAULT '',
           sub_user_id INTEGER,
           inbound TEXT NOT NULL DEFAULT '',
           source TEXT NOT NULL DEFAULT '',
           host TEXT NOT NULL DEFAULT '',
           port INTEGER NOT NULL DEFAULT 0,
           network TEXT NOT NULL DEFAULT '',
           up INTEGER NOT NULL DEFAULT 0,
           down INTEGER NOT NULL DEFAULT 0,
           PRIMARY KEY (server_id, conn_id)
         );
         CREATE INDEX IF NOT EXISTS idx_connlog_ts ON connection_log(ts_first DESC);
         CREATE INDEX IF NOT EXISTS idx_connlog_sub ON connection_log(sub_user_id, ts_first DESC);",
    )?;
    Ok(())
}

/// 每客户每小时的用户量汇总（概览客户排行按窗口查询的数据源）：bucket 为
/// 整点 unix 秒。建表即从 connection_log 回填一次——记录开关与保留期只影
/// 响将来，已有日志的历史价值折算进表里；此后 bump_sub_usage 记账同步增量，
/// 与日志是否记录再无关系。
fn migrate_to_23(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sub_usage_hourly (
           sub_user_id INTEGER NOT NULL,
           bucket INTEGER NOT NULL,
           up INTEGER NOT NULL DEFAULT 0,
           down INTEGER NOT NULL DEFAULT 0,
           PRIMARY KEY (sub_user_id, bucket)
         );
         CREATE INDEX IF NOT EXISTS idx_sub_usage_hourly_bucket ON sub_usage_hourly(bucket);
         INSERT OR IGNORE INTO sub_usage_hourly (sub_user_id, bucket, up, down)
           SELECT sub_user_id, (ts_last/3600)*3600, SUM(up), SUM(down)
           FROM connection_log
           WHERE sub_user_id IS NOT NULL AND sub_user_id > 0
           GROUP BY sub_user_id, (ts_last/3600)*3600;",
    )?;
    Ok(())
}

/// 隧道规则模型 v2：relay_rules 加列（全部带默认值，旧行零迁移成本）+
/// relay_targets 落地目标子表。transport 三个参数字段（sni/insecure/path）
/// 结构化存储，渲染时拼 kaminari 字符串（如 "tls;sni=x;insecure"）。
/// 存量 target 拆行回填为第一目标；target 列此后是第一目标的派生镜像，
/// 供 validate / 分享链接等旧路径继续使用。add_column 与 CREATE IF NOT
/// EXISTS 都幂等，重复执行安全。
fn migrate_to_24(conn: &Connection) -> Result<()> {
    for column in [
        // 每规则协议（渲染为端点级 network 覆盖）：both / tcp / udp
        "protocol TEXT NOT NULL DEFAULT 'both'",
        // 规则备注
        "note TEXT NOT NULL DEFAULT ''",
        // 负载均衡策略：'' / roundrobin / iphash（多目标时必填）
        "balance TEXT NOT NULL DEFAULT ''",
        // 中转⇄落地间的加密传输层：'' / tls / ws / wss
        "transport TEXT NOT NULL DEFAULT ''",
        "tls_sni TEXT NOT NULL DEFAULT ''",
        "tls_insecure INTEGER NOT NULL DEFAULT 0",
        "ws_path TEXT NOT NULL DEFAULT ''",
        // 隧道落地机（>0 即隧道规则，须为托管 agent 的服务器）与落地监听端口
        "exit_server_id INTEGER NOT NULL DEFAULT 0",
        "exit_listen_port TEXT NOT NULL DEFAULT ''",
        // 高级绑定与协议头/多路径
        "listen_host TEXT NOT NULL DEFAULT ''",
        "through TEXT NOT NULL DEFAULT ''",
        "interface TEXT NOT NULL DEFAULT ''",
        "send_proxy INTEGER NOT NULL DEFAULT 0",
        "mptcp INTEGER NOT NULL DEFAULT 0",
    ] {
        add_column(conn, "relay_rules", column)?;
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS relay_targets (
           id INTEGER PRIMARY KEY,
           rule_id INTEGER NOT NULL,
           seq INTEGER NOT NULL,
           host TEXT NOT NULL,
           port INTEGER NOT NULL,
           weight INTEGER NOT NULL DEFAULT 1,
           enabled INTEGER NOT NULL DEFAULT 1,
           -- up / down / unknown（纯 UDP 目标不探测）
           state TEXT NOT NULL DEFAULT 'unknown',
           fail_streak INTEGER NOT NULL DEFAULT 0,
           ok_streak INTEGER NOT NULL DEFAULT 0,
           down_since INTEGER NOT NULL DEFAULT 0,
           last_checked INTEGER NOT NULL DEFAULT 0
         );
         CREATE INDEX IF NOT EXISTS idx_relay_targets_rule ON relay_targets(rule_id, seq);",
    )?;
    // 存量规则的 target 拆行回填为第一目标。迁移只在版本跃迁时跑一次；
    // 这里的 INSERT 也只对尚无目标的规则行补第一目标，重跑不产生重复。
    let rules: Vec<(i64, String)> = {
        let mut stmt = conn.prepare("SELECT id, target FROM relay_rules")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (id, target) in rules {
        if let Some((host, port)) = target.rsplit_once(':') {
            if let Ok(port) = port.parse::<i64>() {
                conn.execute(
                    "INSERT INTO relay_targets (rule_id, seq, host, port)
                     SELECT ?1, 1, ?2, ?3
                     WHERE NOT EXISTS (SELECT 1 FROM relay_targets WHERE rule_id = ?1)",
                    params![id, host, port],
                )?;
            }
        }
    }
    Ok(())
}

/// 连接日志行（M14）：proxy 侧生命周期聚合后的落库形态（host/port 已归一）。
#[derive(Debug, Clone)]
pub struct ConnectionLogRow {
    pub conn_id: String,
    pub user: String,
    pub inbound: String,
    pub network: String,
    pub source: String,
    pub host: String,
    pub port: i64,
    pub first: i64,
    pub last: i64,
    pub up: i64,
    pub down: i64,
}

/// 批量 upsert 连接日志（同一连接的快照与定稿共用一行）。sub_user_id 由
/// user 名按服务器映射（SQL 子查询），未认领凭据为 NULL。
fn migrate_to_16(conn: &Connection) -> Result<()> {
    add_column(conn, "proxy_node", "flow TEXT NOT NULL DEFAULT 'xtls-rprx-vision'")
}

/// M4：统计采样两张表（M1 设计里有、M4 才首次落地）+ 流量按服务器记账。
fn migrate_to_14(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS traffic_samples (
          id INTEGER PRIMARY KEY,
          instance_id INTEGER NOT NULL DEFAULT 0,
          node_tag TEXT NOT NULL,
          ts INTEGER NOT NULL,
          rx INTEGER NOT NULL DEFAULT 0,
          tx INTEGER NOT NULL DEFAULT 0,
          server_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_traffic_samples_node ON traffic_samples(server_id, node_tag, ts);
        CREATE TABLE IF NOT EXISTS latency_samples (
          id INTEGER PRIMARY KEY,
          node_id INTEGER NOT NULL,
          ts INTEGER NOT NULL,
          avg_ms REAL NOT NULL,
          loss REAL NOT NULL DEFAULT 0
        );",
    )?;
    // 对极早期手工建过这两张表的文件做幂等兜底。
    add_column(conn, "traffic_samples", "server_id INTEGER NOT NULL DEFAULT 0")?;
    Ok(())
}

/// 上游 v1.3.1 的 metric 峰值列：在我们链中折叠为 17 号（上游自己的 10 号
/// 与我们的 proxy 表撞号）。add_column 幂等，v16 部署升级时补列。
fn migrate_to_17(conn: &Connection) -> Result<()> {
    add_column(conn, "metric", "net_rx_max INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "metric", "net_tx_max INTEGER NOT NULL DEFAULT 0")
}

/// 订阅转换 v2（miaomiaowu 架构）：五张 sub_* 表。sub_nodes 双形态——
/// raw_link（分享链接）与 clash_config（Clash 原生字段 JSON）至少存其一，
/// 渲染时链接走解析、原生字段直接用（导入零丢失）；tags 为 JSON 字符串
/// 数组（标签制组织，导入自动打地区 emoji 标签）。模板内容入库（非文件），
/// 随备份功能走；内置模板 is_builtin=1 不可删。
fn migrate_to_25(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sub_nodes (
           id INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           raw_link TEXT NOT NULL DEFAULT '',
           clash_config TEXT NOT NULL DEFAULT '',
           protocol TEXT NOT NULL DEFAULT '',
           server TEXT NOT NULL DEFAULT '',
           port INTEGER NOT NULL DEFAULT 0,
           tags TEXT NOT NULL DEFAULT '[]',
           source_url TEXT NOT NULL DEFAULT '',
           note TEXT NOT NULL DEFAULT '',
           enabled INTEGER NOT NULL DEFAULT 1,
           latency_ms INTEGER NOT NULL DEFAULT 0,
           probed_at INTEGER NOT NULL DEFAULT 0,
           created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS sub_sources (
           id INTEGER PRIMARY KEY,
           url TEXT NOT NULL UNIQUE,
           name TEXT NOT NULL DEFAULT '',
           user_agent TEXT NOT NULL DEFAULT 'clash-meta/2.4.0',
           auto_update INTEGER NOT NULL DEFAULT 1,
           interval_min INTEGER NOT NULL DEFAULT 60,
           info TEXT NOT NULL DEFAULT '',
           node_count INTEGER NOT NULL DEFAULT 0,
           last_sync INTEGER NOT NULL DEFAULT 0,
           created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS sub_templates (
           id INTEGER PRIMARY KEY,
           name TEXT NOT NULL UNIQUE,
           note TEXT NOT NULL DEFAULT '',
           is_builtin INTEGER NOT NULL DEFAULT 0,
           content TEXT NOT NULL,
           created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS sub_rule_snippets (
           id INTEGER PRIMARY KEY,
           name TEXT NOT NULL UNIQUE,
           kind TEXT NOT NULL DEFAULT 'rules',
           mode TEXT NOT NULL DEFAULT 'prepend',
           content TEXT NOT NULL DEFAULT '',
           enabled INTEGER NOT NULL DEFAULT 1,
           created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS sub_profiles (
           id INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           token TEXT NOT NULL UNIQUE,
           template_name TEXT NOT NULL DEFAULT '',
           selected_tags TEXT NOT NULL DEFAULT '[]',
           snippet_ids TEXT NOT NULL DEFAULT '[]',
           expires_at INTEGER NOT NULL DEFAULT 0,
           enabled INTEGER NOT NULL DEFAULT 1,
           created_at INTEGER NOT NULL
         );",
    )?;
    // 内置模板 seed（表空时注入两份，演示 __ALL__ 占位符约定）。
    let seeded: i64 =
        conn.query_row("SELECT COUNT(*) FROM sub_templates WHERE is_builtin = 1", [], |r| r.get(0))?;
    if seeded == 0 {
        for (name, content) in [
            ("经典分组-绕过大陆.yaml", crate::subscription::BUILTIN_TEMPLATE_BALANCED),
            ("全局代理.yaml", crate::subscription::BUILTIN_TEMPLATE_GLOBAL),
        ] {
            conn.execute(
                "INSERT OR IGNORE INTO sub_templates (name, note, is_builtin, content, created_at)
                 VALUES (?1, '内置模板', 1, ?2, ?3)",
                params![name, content, Utc::now().timestamp()],
            )?;
        }
    }
    Ok(())
}

/// 订阅页 v2.1（26 第二次使用）：sub_profiles 的组覆盖表 + 规则模式三模板
/// seed（极简/均衡/完整，MetaCubeX mrs 目录，内容由 subscription.rs 类别表
/// 代码生成）。INSERT OR IGNORE + 名称唯一，重跑安全。
fn migrate_to_26(conn: &Connection) -> Result<()> {
    add_column(conn, "sub_profiles", "group_overrides TEXT NOT NULL DEFAULT '{}'")?;
    for (name, content) in crate::subscription::rule_mode_templates() {
        conn.execute(
            "INSERT OR IGNORE INTO sub_templates (name, note, is_builtin, content, created_at)
             VALUES (?1, '规则模式内置模板', 1, ?2, ?3)",
            params![name, content, Utc::now().timestamp()],
        )?;
    }
    Ok(())
}

/// 规则模式 v3（27 第二次使用）：sub_profiles 加 selected_categories。
fn migrate_to_27(conn: &Connection) -> Result<()> {
    add_column(conn, "sub_profiles", "selected_categories TEXT NOT NULL DEFAULT '[]'")
}

/// 订阅文件节点勾选（28 第二次使用）：sub_profiles 加 selected_nodes。
fn migrate_to_28(conn: &Connection) -> Result<()> {
    add_column(conn, "sub_profiles", "selected_nodes TEXT NOT NULL DEFAULT '[]'")
}

/// 规则模式对齐妙妙屋（29 第二次使用）：三份内置模板重写为
/// 节点选择/自动选择/漏网之鱼 结构。老库在 26 里 INSERT OR IGNORE 留下的
/// 是旧结构（组含 __ALL__ 占位不展开、入口组聚合类别组），就地覆盖——
/// 内置模板内容归代码所有，不做用户改动保护。
fn migrate_to_29(conn: &Connection) -> Result<()> {
    for (name, content) in crate::subscription::rule_mode_templates() {
        conn.execute(
            "UPDATE sub_templates SET content = ?2 WHERE name = ?1 AND is_builtin = 1",
            params![name, content],
        )?;
    }
    Ok(())
}

/// 来源管理（30）：自定义来源（模板 URL / 类别集 JSON 快照）与内置项的
/// 用户覆盖（修改内置 39 预设/24 类时存这里，删行=恢复代码默认）。
fn migrate_to_30(conn: &Connection) -> Result<()> {
    Ok(conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS conv_rule_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL DEFAULT '',
            data TEXT NOT NULL DEFAULT '',
            last_sync INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS conv_builtin_overrides (
            target TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );",
    )?)
}

/// 静态订阅（31）：static_content 非空 = 整份 YAML 原样下发（用户可编辑的
/// 快照，不再跟随节点/勾选变化）。
fn migrate_to_31(conn: &Connection) -> Result<()> {
    add_column(conn, "sub_profiles", "static_content TEXT NOT NULL DEFAULT ''")
}

/// agent 分发订阅（32）：每订阅开关——开启后 agent 入口可回源拉取该订阅。
fn migrate_to_32(conn: &Connection) -> Result<()> {
    add_column(conn, "sub_profiles", "agent_dist INTEGER NOT NULL DEFAULT 0")
}

/// 用户中心页（33）：每客户的 /u/{token} 页面开关（默认开；链接即凭证，
/// 配合 public_page 总开关可一键关闭整类页面）。
fn migrate_to_33(conn: &Connection) -> Result<()> {
    add_column(conn, "sub_user", "user_page INTEGER NOT NULL DEFAULT 1")
}

/// 内置规则片段（34）：常见分流模板补种进 sub_rule_snippets（OR IGNORE 幂等，
/// 用户改动与删除不被覆盖——只补缺失的）。
fn migrate_to_34(conn: &Connection) -> Result<()> {
    crate::subscription::seed_builtin_snippets(conn)
}

/// 内置规则片段换血（35）：删旧 8 个（用户拍板不需要），种新清单
/// （防泄漏/源 IP 分流/QUIC/连通性检测/NTP/Telegram/下载直连/遥测拦截）。
fn migrate_to_35(conn: &Connection) -> Result<()> {
    crate::subscription::seed_builtin_snippets(conn)
}

/// 内置片段默认停用（36）：迁移 34/35 种进去的都是 enabled=1，按名单统一
/// 关成 0（模板是备选素材，由用户明确启用）。幂等。
fn migrate_to_36(conn: &Connection) -> Result<()> {
    for name in crate::subscription::BUILTIN_SNIPPETS {
        let name = name.0;
        conn.execute("UPDATE sub_rule_snippets SET enabled = 0 WHERE name = ?1", rusqlite::params![name])?;
    }
    Ok(())
}

/// 按协议限速（37）：proxy_node 加上行/下行限速（Mbps，0=不限）。tc 层由
/// agent/hub 的 shaper 模块执行，这里只存期望值。迁移需可重跑（测试会把
/// user_version 拨回去再跑）加列走幂等的 add_column；老形状假库可能没有
/// proxy_node 表（夹具只建自己需要的表），没有就跳过。
fn migrate_to_37(conn: &Connection) -> Result<()> {
    if !schema_mentions(conn, "proxy_node", "CREATE TABLE")? {
        return Ok(());
    }
    add_column(conn, "proxy_node", "rate_up INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "proxy_node", "rate_down INTEGER NOT NULL DEFAULT 0")?;
    Ok(())
}

/// 隧道链路延迟（38）：relay_targets 记最近一次探测毫秒数；新表
/// relay_probe_sample 存每腿探测样本（leg = `t{target_id}` 普通腿 /
/// `h{rule_id}` 加密隧道入口→出口腿，7 天保留）；relay_hop_state 存加密腿的
/// 健康状态机（普通腿的状态本就长在 relay_targets 行上，加密腿没有宿主行）。
/// 老形状假库可能没有 relay_targets 表，没有就跳过加列。
fn migrate_to_38(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "relay_targets", "CREATE TABLE")? {
        add_column(conn, "relay_targets", "last_latency_ms INTEGER")?;
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS relay_probe_sample (
           id INTEGER PRIMARY KEY,
           leg TEXT NOT NULL,
           ts INTEGER NOT NULL,
           ok INTEGER NOT NULL,
           latency_ms INTEGER
         );
         CREATE INDEX IF NOT EXISTS idx_relay_probe_sample_leg ON relay_probe_sample(leg, ts);
         CREATE TABLE IF NOT EXISTS relay_hop_state (
           rule_id INTEGER PRIMARY KEY,
           state TEXT NOT NULL DEFAULT 'unknown',
           fail_streak INTEGER NOT NULL DEFAULT 0,
           ok_streak INTEGER NOT NULL DEFAULT 0,
           down_since INTEGER NOT NULL DEFAULT 0,
           last_checked INTEGER NOT NULL DEFAULT 0,
           last_latency_ms INTEGER
         );",
    )?;
    Ok(())
}

/// 客户成为唯一交付入口（39）：sub_user 绑定内容方案（profile_id，NULL=未绑
/// 定回落旧裸节点输出）与独立分发开关（agent_dist）；sub_node 记录来源节点
/// （proxy_node_id，面板导入的节点才有）——客户渲染时按它换用客户自有凭据。
/// 老形状假库可能缺 sub_user/sub_nodes 表（夹具只建自己需要的表），没有就跳过。
fn migrate_to_39(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "sub_user", "CREATE TABLE")? {
        add_column(conn, "sub_user", "profile_id INTEGER")?;
        add_column(conn, "sub_user", "agent_dist INTEGER NOT NULL DEFAULT 0")?;
    }
    if schema_mentions(conn, "sub_nodes", "CREATE TABLE")? {
        add_column(conn, "sub_nodes", "proxy_node_id INTEGER")?;
    }
    Ok(())
}

/// 每凭据配额+到期（40）：proxy_user（客户×节点分配关系）加独立的 到期/配额
/// 字段（按凭据计量与摘除，客户级配额仍并行生效）；sub_user 加 /u/ 页视图
/// 模式（overview 总览 / per_node 逐节点明细，管理员可选）。老形状假库缺表
/// 则跳过。
fn migrate_to_40(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "proxy_user", "CREATE TABLE")? {
        add_column(conn, "proxy_user", "expires_at TEXT")?;
        add_column(conn, "proxy_user", "quota_bytes INTEGER NOT NULL DEFAULT 0")?;
        add_column(conn, "proxy_user", "quota_used_up INTEGER NOT NULL DEFAULT 0")?;
        add_column(conn, "proxy_user", "quota_used_down INTEGER NOT NULL DEFAULT 0")?;
        add_column(conn, "proxy_user", "quota_period_start INTEGER NOT NULL DEFAULT 0")?;
        add_column(conn, "proxy_user", "quota_reset TEXT NOT NULL DEFAULT ''")?;
    }
    if schema_mentions(conn, "sub_user", "CREATE TABLE")? {
        add_column(conn, "sub_user", "view_mode TEXT NOT NULL DEFAULT 'overview'")?;
    }
    Ok(())
}

/// 迁移 41（自助重置订阅）：sub_user 加 自助重置开关/次数上限/已用次数/上次
/// 重置时间。老形状假库缺表则跳过。
fn migrate_to_41(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "sub_user", "CREATE TABLE")? {
        add_column(conn, "sub_user", "allow_self_reset INTEGER NOT NULL DEFAULT 0")?;
        add_column(conn, "sub_user", "reset_limit INTEGER NOT NULL DEFAULT 3")?;
        add_column(conn, "sub_user", "reset_count INTEGER NOT NULL DEFAULT 0")?;
        add_column(conn, "sub_user", "last_reset_at INTEGER NOT NULL DEFAULT 0")?;
    }
    Ok(())
}

/// 迁移 42（通知底座二期）：通知渠道实例化——notify_channels（名称/类型/
/// config JSON/启停）+ notify_routes（事件 → 渠道 id 数组）。存量 kv 里配好的
/// Telegram 与 Webhook 升级成两个渠道实例（沿用原凭据与模板），每类事件路由
/// 到「全部已配渠道」——与升级前的广播行为完全一致，无感切换。
fn migrate_to_42(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS notify_channels (
            id         INTEGER PRIMARY KEY,
            name       TEXT NOT NULL UNIQUE,
            kind       TEXT NOT NULL,
            config     TEXT NOT NULL DEFAULT '{}',
            enabled    INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notify_routes (
            event    TEXT PRIMARY KEY,
            channels TEXT NOT NULL DEFAULT '[]'
        );",
    )?;
    let mut telegram: Option<(String, String)> = None;
    if let (Ok(token), Ok(chat)) =
        (kv_nonempty(conn, "notify_telegram_token"), kv_nonempty(conn, "notify_telegram_chat"))
    {
        let mut config = serde_json::json!({ "token": token, "chat": chat });
        if let Ok(text) = kv_nonempty(conn, "notify_telegram_text") {
            config["text"] = serde_json::json!(text);
        }
        telegram = Some((config.to_string(), "Telegram".into()));
    }
    let mut webhook: Option<(String, String)> = None;
    if let Ok(url) = kv_nonempty(conn, "notify_webhook_url") {
        let mut config = serde_json::json!({ "url": url });
        if let Ok(headers) = kv_nonempty(conn, "notify_webhook_headers") {
            config["headers"] = serde_json::json!(headers);
        }
        if let Ok(body) = kv_nonempty(conn, "notify_webhook_body") {
            config["body"] = serde_json::json!(body);
        }
        webhook = Some((config.to_string(), "Webhook".into()));
    }
    for (kind, channel) in [("telegram", telegram), ("webhook", webhook)] {
        let Some((config, name)) = channel else { continue };
        conn.execute(
            "INSERT OR IGNORE INTO notify_channels (name, kind, config, enabled, created_at)
             VALUES (?1, ?2, ?3, 1, strftime('%s','now'))",
            params![name, kind, config],
        )?;
    }
    // 每类事件 → 全部渠道（保持升级前「配了哪个发哪个」的广播语义）。路由行
    // 只在有渠道时物化：没有行的事件回落「全部启用渠道」，将来新增事件类型
    // 无需迁移。
    let ids: Vec<i64> = {
        let mut stmt = conn.prepare("SELECT id FROM notify_channels ORDER BY id")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<std::result::Result<Vec<i64>, _>>()?
    };
    if !ids.is_empty() {
        let all = serde_json::to_string(&ids)?;
        for event in ["offline", "online", "traffic", "expiry", "renew", "login", "sub_alert"] {
            conn.execute(
                "INSERT OR IGNORE INTO notify_routes (event, channels) VALUES (?1, ?2)",
                params![event, all],
            )?;
        }
    }
    Ok(())
}

/// 迁移 43（延迟探测告警）：ping_alert 状态表。老形状假库缺 ping_record
/// 等表无妨——本迁移只建自己的表。
fn migrate_to_43(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ping_alert (
            key           TEXT PRIMARY KEY,
            node_id       INTEGER NOT NULL,
            task_id       INTEGER NOT NULL,
            kind          TEXT NOT NULL,
            raised_at     INTEGER NOT NULL,
            confirmed     INTEGER NOT NULL DEFAULT 0,
            normal_streak INTEGER NOT NULL DEFAULT 0,
            baseline      INTEGER,
            detail        TEXT NOT NULL DEFAULT '',
            checked_at    INTEGER NOT NULL DEFAULT 0,
            recovered_at  INTEGER
        );",
    )?;
    Ok(())
}

/// 迁移 44（回程线路探测）：route_task / route_task_node / route_status /
/// route_event 四表。老形状假库缺其它表无妨——只建自己的。
fn migrate_to_44(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS route_task (
            id       INTEGER PRIMARY KEY,
            name     TEXT    NOT NULL,
            target   TEXT    NOT NULL,
            interval INTEGER NOT NULL DEFAULT 600,
            enabled  INTEGER NOT NULL DEFAULT 1,
            sort     INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS route_task_node (
            task_id INTEGER NOT NULL REFERENCES route_task(id) ON DELETE CASCADE,
            node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
            PRIMARY KEY (task_id, node_id)
        );
        CREATE TABLE IF NOT EXISTS route_status (
            task_id   INTEGER NOT NULL,
            node_id   INTEGER NOT NULL,
            hops      TEXT NOT NULL DEFAULT '[]',
            line      TEXT NOT NULL DEFAULT '',
            baseline  TEXT NOT NULL DEFAULT '',
            probes    INTEGER NOT NULL DEFAULT 0,
            streak    INTEGER NOT NULL DEFAULT 0,
            probed_at INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (task_id, node_id)
        );
        CREATE TABLE IF NOT EXISTS route_event (
            id        INTEGER PRIMARY KEY,
            task_id   INTEGER NOT NULL,
            node_id   INTEGER NOT NULL,
            from_line TEXT NOT NULL,
            to_line   TEXT NOT NULL,
            at        INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

/// 迁移 45（MCP 代理，五期）：OAuth 客户端、访问租约（token 哈希落库）、
/// 授权码（哈希落库、5 分钟短命）、操作审计。老形状假库缺其它表无妨。
fn migrate_to_45(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mcp_clients (
            client_id     TEXT PRIMARY KEY,
            client_secret TEXT NOT NULL,
            name          TEXT NOT NULL,
            created_at    INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mcp_tokens (
            token_hash TEXT PRIMARY KEY,
            client_id  TEXT NOT NULL,
            scopes     TEXT NOT NULL DEFAULT 'read exec',
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked    INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS mcp_codes (
            code_hash    TEXT PRIMARY KEY,
            client_id    TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            challenge    TEXT NOT NULL DEFAULT '',
            method       TEXT NOT NULL DEFAULT 'S256',
            lease_hours  INTEGER NOT NULL DEFAULT 24,
            expires_at   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mcp_operations (
            id     INTEGER PRIMARY KEY,
            lease  TEXT NOT NULL,
            tool   TEXT NOT NULL,
            node   TEXT NOT NULL DEFAULT '',
            params TEXT NOT NULL DEFAULT '',
            at     INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

/// 迁移 46（回程限流判定）：route_status 加 recent 列——最近 10 次识别
/// 结果的滑动窗口，「未识别」占比过高（ICMP 被限流）时暂停切线判定，
/// 防止「电信城域↔未识别」翻转刷线路变化事件。
fn migrate_to_46(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "route_status", "CREATE TABLE")? {
        add_column(conn, "route_status", "recent TEXT NOT NULL DEFAULT '[]'")?;
    }
    Ok(())
}

/// 通用 DDNS 基座（grilling 一期）：节点绑定 FQDN + 最近一次同步的 IP。
/// dns_ip 只由同步路径写，不进 NodePatch。
fn migrate_to_48(conn: &Connection) -> Result<()> {
    add_column(conn, "node", "dns_name TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "node", "dns_ip TEXT NOT NULL DEFAULT ''")
}

/// 入口故障转移（grilling 二期）：规则的备用入口机（JSON 数组，node id）。
/// 备用机的 realm 渲染同一条入口腿（同端口→同目标），主入口双确认判挂后
/// DNS 翻转到备用机 IP。
fn migrate_to_49(conn: &Connection) -> Result<()> {
    add_column(conn, "relay_rules", "entry_backups TEXT NOT NULL DEFAULT '[]'")
}

/// 购买网站（grilling 三期）：记录主机购买来源，面板主机名点击跳转。
fn migrate_to_50(conn: &Connection) -> Result<()> {
    add_column(conn, "node", "purchase_url TEXT NOT NULL DEFAULT ''")
}

/// 用户记录导出（grilling 四期）：凭据的分配时间。历史分配为 0，导出显示「未知」。
/// fork 老库此表可能尚未建（同 migrate_to_46 的守卫），缺列由读取侧 unwrap_or 兜底。
fn migrate_to_51(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "proxy_user", "CREATE TABLE")? {
        add_column(conn, "proxy_user", "created_at INTEGER NOT NULL DEFAULT 0")?;
    }
    Ok(())
}

/// 登录会话卡（grilling 五期）：记录签发时的登录 IP 与 UA。存量会话为空串，
/// 安全页显示「未知」。
fn migrate_to_52(conn: &Connection) -> Result<()> {
    add_column(conn, "session", "ip TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "session", "user_agent TEXT NOT NULL DEFAULT ''")
}

/// 切换主机（抗墙）：proxy_node 绑自有域名 + 镜像机集合 + 域名指向记账。
/// dns_server_id 回填 = server_id（未切换过 = 指向原机）。老形状假库可能没有
/// proxy_node 表（夹具只建自己需要的表），没有就跳过（先例 migrate_to_37）。
fn migrate_to_53(conn: &Connection) -> Result<()> {
    if !schema_mentions(conn, "proxy_node", "CREATE TABLE")? {
        return Ok(());
    }
    add_column(conn, "proxy_node", "dns_name TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_node", "dns_server_id INTEGER NOT NULL DEFAULT 0")?;
    add_column(conn, "proxy_node", "dns_ip TEXT NOT NULL DEFAULT ''")?;
    add_column(conn, "proxy_node", "mirror_servers TEXT NOT NULL DEFAULT '[]'")?;
    conn.execute_batch("UPDATE proxy_node SET dns_server_id = server_id WHERE dns_server_id = 0")?;
    Ok(())
}

/// 身份归一（grilling Q1–Q5）：「本机」虚拟身份 server_id=0 退役——库里已
/// 无 0 行，重建两表只为装上最终防线 CHECK，此后任何代码路径都写不进 0；
/// 「本机」= hostname 等于 hub 的那个节点行。exit_server_id 不加约束：0 是
/// 「直连」哨兵，不是身份。fresh 库先跑基础 CREATE 再到这里重建，终态一致。
/// proxy_node 守卫（先例 v37/v53）：老库夹具先于代理模块、无此表——曾靠
/// 吞 execute_batch 错误跳过，连带 relay_rules 重建也没跑；拆段+守卫后两
/// 表各自完整迁移，错误也不再被吞。
fn migrate_to_47(conn: &Connection) -> Result<()> {
    if schema_mentions(conn, "proxy_node", "CREATE TABLE")? {
        conn.execute_batch(
            r#"
            CREATE TABLE proxy_node_new (
              id INTEGER PRIMARY KEY,
              name TEXT NOT NULL,
              protocol TEXT NOT NULL,
              listen_port INTEGER NOT NULL,
              sni TEXT NOT NULL DEFAULT '',
              flow TEXT NOT NULL DEFAULT 'xtls-rprx-vision',
              method TEXT NOT NULL DEFAULT '',
              enabled INTEGER NOT NULL DEFAULT 1,
              remark TEXT NOT NULL DEFAULT '',
              created_at INTEGER NOT NULL,
              server_id INTEGER NOT NULL CHECK (server_id > 0),
              egress_type TEXT NOT NULL DEFAULT '',
              egress_host TEXT NOT NULL DEFAULT '',
              egress_port INTEGER NOT NULL DEFAULT 0,
              egress_username TEXT NOT NULL DEFAULT '',
              egress_password TEXT NOT NULL DEFAULT '',
              rate_up INTEGER NOT NULL DEFAULT 0,
              rate_down INTEGER NOT NULL DEFAULT 0,
              UNIQUE(listen_port, server_id)
            );
            INSERT INTO proxy_node_new
              SELECT id, name, protocol, listen_port, sni, flow, method, enabled, remark, created_at,
                     server_id, egress_type, egress_host, egress_port, egress_username, egress_password,
                     rate_up, rate_down
              FROM proxy_node;
            DROP TABLE proxy_node;
            ALTER TABLE proxy_node_new RENAME TO proxy_node;
            CREATE INDEX idx_proxy_node_server ON proxy_node(server_id);
            "#,
        )?;
    }
    conn.execute_batch(
        r#"
        -- 归一前置：旧「本机」哨兵 server_id=0 指到 hub 节点行（首位注册
        -- 即 hub）；无 node 表可指时规则无处安放，0 已废弃故删。
        UPDATE relay_rules SET server_id = (SELECT MIN(id) FROM node)
         WHERE server_id = 0
           AND EXISTS (SELECT 1 FROM node);
        DELETE FROM relay_rules WHERE server_id = 0;
        CREATE TABLE relay_rules_new (
          id INTEGER PRIMARY KEY,
          server_id INTEGER NOT NULL CHECK (server_id > 0),
          name TEXT NOT NULL,
          listen_port TEXT NOT NULL,
          target TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          origin_link TEXT NOT NULL DEFAULT '',
          protocol TEXT NOT NULL DEFAULT 'both',
          note TEXT NOT NULL DEFAULT '',
          balance TEXT NOT NULL DEFAULT '',
          transport TEXT NOT NULL DEFAULT '',
          tls_sni TEXT NOT NULL DEFAULT '',
          tls_insecure INTEGER NOT NULL DEFAULT 0,
          ws_path TEXT NOT NULL DEFAULT '',
          exit_server_id INTEGER NOT NULL DEFAULT 0,
          exit_listen_port TEXT NOT NULL DEFAULT '',
          listen_host TEXT NOT NULL DEFAULT '',
          through TEXT NOT NULL DEFAULT '',
          interface TEXT NOT NULL DEFAULT '',
          send_proxy INTEGER NOT NULL DEFAULT 0,
          mptcp INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO relay_rules_new
          SELECT id, server_id, name, listen_port, target, enabled, created_at, origin_link,
                 protocol, note, balance, transport, tls_sni, tls_insecure, ws_path,
                 exit_server_id, exit_listen_port, listen_host, through, interface, send_proxy, mptcp
          FROM relay_rules;
        DROP TABLE relay_rules;
        ALTER TABLE relay_rules_new RENAME TO relay_rules;
        "#,
    )?;
    Ok(())
}

/// 迁移读取用的 kv 非空值（迁移自身不走 Db 的 conn() 包装）。
fn kv_nonempty(conn: &Connection, key: &str) -> std::result::Result<String, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT value FROM setting WHERE key = ?1")?;
    let mut rows = stmt.query_map([key], |r| r.get::<_, String>(0))?;
    match rows.next() {
        Some(Ok(v)) if !v.is_empty() => Ok(v),
        _ => Err(rusqlite::Error::QueryReturnedNoRows),
    }
}

/// Brings a database already in service up to `SCHEMA_VERSION` and stamps it.
/// `from` is its current version. Fresh files pass 0 rather than
/// `SCHEMA_VERSION`, so they run the same history an upgraded file does and
/// the two end up with the same shape -- a table born in `migrate_to_N` needs
/// exactly that.
///
/// One transaction covers every step and the stamp. SQLite rolls back schema
/// changes and `user_version` alike, so a failure part-way -- a full disk, a
/// killed process -- leaves the file at the version it started from rather
/// than between two.
///
/// Restoring a backup also arrives here: the copy carries its own version and
/// requires the same migrations a restart would have run.
fn migrate(conn: &Connection, from: i64) -> Result<()> {
    // 47 的表重建要 DROP 外键引用的父表：外键开启时 DROP 的隐式 DELETE 会
    // 级联清空 proxy_secret。迁移是受控数据搬运（拷贝保 id），引用一致性
    // 由 foreign_key_check 收尾兜底。该 PRAGMA 不能在事务内切换，挪到事务外。
    conn.execute_batch("PRAGMA foreign_keys = OFF")?;
    let outcome = migrate_inner(conn, from);
    conn.execute_batch("PRAGMA foreign_keys = ON")?;
    outcome
}

fn fk_violation_rows(conn: &Connection) -> Result<Vec<(String, i64, String)>> {
    let mut stmt = conn.prepare("SELECT \"table\", rowid, parent FROM pragma_foreign_key_check")?;
    let rows =
        stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn migrate_inner(conn: &Connection, from: i64) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    // 外键不一致只拦「迁移新增的」：线上存量可能本就有历史孤儿（实测
    // proxy_secret/proxy_user 各一条指向已删节点），迁移不该为此拒绝服务，
    // 但自己的表重建若制造了新孤儿必须回滚。
    let fk_before = fk_violation_rows(conn)?;
    if from < 1 {
        migrate_to_1(&tx)?;
    }
    if from < 2 {
        migrate_to_2(&tx)?;
    }
    if from < 3 {
        migrate_to_3(&tx)?;
    }
    if from < 4 {
        migrate_to_4(&tx)?;
    }
    if from < 5 {
        migrate_to_5(&tx)?;
    }
    if from < 6 {
        migrate_to_6(&tx)?;
    }
    if from < 7 {
        migrate_to_7(&tx)?;
    }
    if from < 8 {
        migrate_to_8(&tx)?;
    }
    if from < 9 {
        migrate_to_9(&tx)?;
    }
    if from < 10 {
        migrate_to_10(&tx)?;
    }
    if from < 11 {
        migrate_to_11(&tx)?;
    }
    if from < 12 {
        migrate_to_12(&tx)?;
    }
    if from < 13 {
        migrate_to_13(&tx)?;
    }
    if from < 14 {
        migrate_to_14(&tx)?;
    }
    if from < 15 {
        migrate_to_15(&tx)?;
    }
    if from < 16 {
        migrate_to_16(&tx)?;
    }
    if from < 17 {
        migrate_to_17(&tx)?;
    }
    if from < 18 {
        migrate_to_18(&tx)?;
    }
    if from < 19 {
        migrate_to_19(&tx)?;
    }
    if from < 21 {
        migrate_to_21(&tx)?;
    }
    if from < 22 {
        migrate_to_22(&tx)?;
    }
    if from < 23 {
        migrate_to_23(&tx)?;
    }
    if from < 24 {
        migrate_to_24(&tx)?;
    }
    if from < 25 {
        migrate_to_25(&tx)?;
    }
    if from < 26 {
        migrate_to_26(&tx)?;
    }
    if from < 27 {
        migrate_to_27(&tx)?;
    }
    if from < 28 {
        migrate_to_28(&tx)?;
    }
    if from < 29 {
        migrate_to_29(&tx)?;
    }
    if from < 30 {
        migrate_to_30(&tx)?;
    }
    if from < 31 {
        migrate_to_31(&tx)?;
    }
    if from < 32 {
        migrate_to_32(&tx)?;
    }
    if from < 33 {
        migrate_to_33(&tx)?;
    }
    if from < 34 {
        migrate_to_34(&tx)?;
    }
    if from < 35 {
        migrate_to_35(&tx)?;
    }
    if from < 36 {
        migrate_to_36(&tx)?;
    }
    if from < 37 {
        migrate_to_37(&tx)?;
    }
    if from < 38 {
        migrate_to_38(&tx)?;
    }
    if from < 39 {
        migrate_to_39(&tx)?;
    }
    if from < 40 {
        migrate_to_40(&tx)?;
    }
    if from < 41 {
        migrate_to_41(&tx)?;
    }
    if from < 42 {
        migrate_to_42(&tx)?;
    }
    if from < 43 {
        migrate_to_43(&tx)?;
    }
    if from < 44 {
        migrate_to_44(&tx)?;
    }
    if from < 45 {
        migrate_to_45(&tx)?;
    }
    if from < 46 {
        migrate_to_46(&tx)?;
    }
    if from < 47 {
        migrate_to_47(&tx)?;
    }
    if from < 48 {
        migrate_to_48(&tx)?;
    }
    if from < 49 {
        migrate_to_49(&tx)?;
    }
    if from < 50 {
        migrate_to_50(&tx)?;
    }
    if from < 51 {
        migrate_to_51(&tx)?;
    }
    if from < 52 {
        migrate_to_52(&tx)?;
    }
    if from < 53 {
        migrate_to_53(&tx)?;
    }
    let fk_after = fk_violation_rows(conn)?;
    if fk_after.len() > fk_before.len() {
        let added: Vec<_> = fk_after.iter().filter(|r| !fk_before.contains(r)).take(5).collect();
        anyhow::bail!("迁移制造了新的外键不一致（新增 {added:?}），数据库已回滚");
    }
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
    tx.commit()?;
    Ok(())
}

/// Every table a backup must carry before this build will restore it.
const TABLES: [&str; 12] = [
    "setting",
    "node",
    "traffic",
    "metric",
    "ping_task",
    "ping_node",
    "ping_record",
    "session",
    "proxy_node",
    "proxy_secret",
    "proxy_user",
    "sub_user",
];

/// One node's stored configuration and last known facts.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Node {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default = "yes")]
    pub public: bool,
    #[serde(default)]
    pub sort: i64,
    #[serde(default)]
    pub price: f64,
    #[serde(default = "usd")]
    pub currency: String,
    #[serde(default = "monthly")]
    pub billing_cycle: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub remark: String,
    /// Monthly allowance in bytes; 0 means unmetered.
    #[serde(default)]
    pub traffic_limit: i64,
    /// How the allowance is counted: sum, max, up or down.
    #[serde(default = "sum")]
    pub traffic_mode: String,
    #[serde(default = "one")]
    pub traffic_reset_day: u32,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub kernel: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub virt: String,
    #[serde(default)]
    pub cpu_name: String,
    #[serde(default)]
    pub cpu_cores: i64,
    #[serde(default)]
    pub mem_total: i64,
    #[serde(default)]
    pub swap_total: i64,
    #[serde(default)]
    pub disk_total: i64,
    #[serde(default)]
    pub agent_version: String,
    #[serde(default)]
    pub ip: String,
    /// Reported by the agent from its own interfaces, unlike `ip`, which is
    /// merely the address the agent's connection originated from.
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
    /// 通用 DDNS（一期）：节点绑定的 FQDN（如 hk.example.com），公网 IP 变化
    /// 时 hub 自动更新这条 A 记录；空 = 未绑定。
    #[serde(default)]
    pub dns_name: String,
    /// 最近一次同步进 DNS 的 IP，用来发现变化。
    #[serde(default)]
    pub dns_ip: String,
    /// Set in the panel: where this host was bought. The host name links here;
    /// empty = no link.
    #[serde(default)]
    pub purchase_url: String,
    /// ISO 3166-1 alpha-2, uppercase, or empty when unknown; see
    /// `agent_ws::country_source` for the address it is looked up from. Public:
    /// it appears on the status page beside the node's name.
    #[serde(default)]
    pub country: String,
    /// Set in the panel: two uppercase letters, or empty for the looked-up
    /// `country`. What the status page shows is this when present.
    #[serde(default)]
    pub country_pin: String,
    /// Set in the panel; empty is ungrouped. Public, like the name.
    #[serde(default)]
    pub group: String,
    /// Set in the panel, in canonical form, for what neither agent nor hub can
    /// know: the home line behind a transparent proxy, or which of several public
    /// addresses to show. Each replaces the address shown for its family; empty
    /// is automatic. Panel only, like `ip`.
    #[serde(default)]
    pub ipv4_pin: String,
    #[serde(default)]
    pub ipv6_pin: String,
    /// Unix seconds of the node's last report, written once a minute alongside
    /// the metric row. Zero for a node that has never reported.
    #[serde(default)]
    pub last_seen: i64,
    /// Whether going offline and coming back are announced. See `notify`.
    #[serde(default)]
    pub notify: bool,
    #[serde(default)]
    pub down_since: i64,
    /// What the agent authenticates with. Readable so the panel can display an
    /// install command on demand; it never leaves the admin view.
    #[serde(default)]
    pub token: String,
}

fn yes() -> bool {
    true
}

/// MCP OAuth 客户端（动态注册）：secret 原文落库（设计上它随注册返回给
/// 客户端持有，泄露面=库文件本身，与节点 token 同口径）。
#[derive(Debug, Clone)]
pub struct McpClient {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub created_at: i64,
}

/// 一条 MCP 访问租约：token 只存哈希，吊销与过期在库。
#[derive(Debug, Clone)]
pub struct McpLease {
    pub token_hash: String,
    pub client_id: String,
    pub scopes: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

/// 回程探测任务（四期）：nodes 为指派的监控节点。
#[derive(Debug, Clone, Default)]
pub struct RouteTask {
    pub id: i64,
    pub name: String,
    pub target: String,
    pub interval: i64,
    pub enabled: bool,
    pub sort: i64,
    pub nodes: Vec<i64>,
}

/// 一条回程链路的最新状态：hops 是逐跳 JSON，line 是最近识别的主线路，
/// baseline 是学习期建立的基线，probes 不足 3 为学习期。
#[derive(Debug, Clone, Default)]
pub struct RouteStatus {
    pub task_id: i64,
    pub node_id: i64,
    pub hops: String,
    pub line: String,
    pub baseline: String,
    pub probes: i64,
    pub streak: i64,
    /// 最近 10 次识别结果（JSON 数组，空串=未识别），限流判定用。
    pub recent: String,
    pub probed_at: i64,
}

/// 一条延迟探测告警的状态行（三期）：raised_at 起报，recovered_at 恢复
/// （NULL=进行中）。
#[derive(Debug, Clone)]
pub struct PingAlertRow {
    pub key: String,
    pub node_id: i64,
    pub task_id: i64,
    pub kind: String,
    pub raised_at: i64,
    pub confirmed: i64,
    pub normal_streak: i64,
    pub detail: String,
    pub recovered_at: Option<i64>,
}

/// 通知渠道实例（二期底座）：kind = telegram/webhook/bark/smtp/serverchan，
/// config 是各类型自己的 JSON——密钥原样落库（库在本机、面板单管理员），
/// 列表接口只回「配了与否」不回原文。
#[derive(Debug, Clone)]
pub struct NotifyChannel {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub config: String,
    pub enabled: bool,
    pub created_at: i64,
}

/// Omitted settings stay unchanged. An explicit null clears the expiry date.
#[derive(Deserialize, Default)]
pub struct NodePatch {
    pub name: Option<String>,
    pub sort: Option<i64>,
    pub public: Option<bool>,
    pub price: Option<f64>,
    pub currency: Option<String>,
    pub billing_cycle: Option<String>,
    #[serde(default, deserialize_with = "expiry_patch")]
    pub expires_at: Option<Option<String>>,
    pub remark: Option<String>,
    pub traffic_limit: Option<i64>,
    pub traffic_mode: Option<String>,
    pub traffic_reset_day: Option<u32>,
    pub notify: Option<bool>,
    pub country_pin: Option<String>,
    pub ipv4_pin: Option<String>,
    pub ipv6_pin: Option<String>,
    pub group: Option<String>,
    pub dns_name: Option<String>,
    pub purchase_url: Option<String>,
}

fn expiry_patch<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Deserialize, Default)]
pub struct TrafficPatch {
    pub total_rx: Option<i64>,
    pub total_tx: Option<i64>,
    pub month_rx: Option<i64>,
    pub month_tx: Option<i64>,
}
fn usd() -> String {
    "USD".into()
}
fn monthly() -> String {
    "monthly".into()
}
fn sum() -> String {
    "sum".into()
}
fn one() -> u32 {
    1
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Traffic {
    pub total_rx: i64,
    pub total_tx: i64,
    pub month_rx: i64,
    pub month_tx: i64,
    pub month_start: String,
    pub day_rx: i64,
    pub day_tx: i64,
}

impl Traffic {
    /// This period's usage as the node's plan meters it. Summing both directions
    /// regardless would hold a plan billed on upload alone against the wrong
    /// figure. The traffic alert and `node_view` both read this, so the
    /// percentage an alert quotes matches the usage the pages show.
    pub fn month_used(&self, traffic_mode: &str) -> i64 {
        match traffic_mode {
            "up" => self.month_tx,
            "down" => self.month_rx,
            "max" => self.month_rx.max(self.month_tx),
            _ => self.month_rx.saturating_add(self.month_tx),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PingTask {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    pub target: String,
    #[serde(default)]
    pub interval: i64,
    #[serde(default)]
    pub nodes: Vec<i64>,
    /// Nodes created later are assigned this probe as they are added. Existing
    /// nodes follow `nodes` alone.
    #[serde(default)]
    pub auto_join: bool,
    /// The assignments the editor started from. When given on an update, only
    /// the difference between it and `nodes` is applied, so an assignment made
    /// while the editor was open -- a node joining through `auto_join` -- is
    /// not removed by a list that predates it.
    #[serde(default, skip_serializing)]
    pub base: Option<Vec<i64>>,
}

fn rows_to_route_tasks(
    rows: rusqlite::MappedRows<
        '_,
        impl FnMut(
            &rusqlite::Row<'_>,
        ) -> std::result::Result<(i64, String, String, i64, bool, i64), rusqlite::Error>,
    >,
) -> Result<Vec<RouteTask>> {
    let mut out = Vec::new();
    for r in rows {
        let (id, name, target, interval, enabled, sort) = r?;
        out.push(RouteTask { id, name, target, interval, enabled, sort, nodes: Vec::new() });
    }
    Ok(out)
}

/// Restricts the database to its owner.
///
/// It is the credential store: node tokens in the clear, the GitHub client
/// secret, the password hash. SQLite creates it under the umask, which at a
/// default 022 is world-readable, and the WAL and shm files hold the same rows.
///
/// Best effort: a filesystem without Unix modes still works.
fn restrict(path: &str) {
    for file in [path.to_owned(), format!("{path}-wal"), format!("{path}-shm")] {
        own_only(&file);
    }
}

/// One file, owner-only. Also applied to the backup copy `VACUUM INTO` writes,
/// which is the entire credential store in one portable file, created under the
/// umask like any other.
fn own_only(file: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600));
    }
}

/// The `main` database's path as SQLite reports it, empty for `:memory:`.
/// Queried rather than cached so there is a single answer to which file is
/// open.
fn main_file(conn: &Connection) -> String {
    conn.query_row("PRAGMA database_list", [], |r| r.get(2)).unwrap_or_default()
}

fn bytes_of(file: &str) -> i64 {
    std::fs::metadata(file).map(|m| m.len() as i64).unwrap_or(0)
}

/// Bytes the database occupies. The WAL is included: committed rows remain there
/// until a checkpoint folds them into the main file, so the two together are what
/// an operator sees on disk.
fn on_disk(file: &str) -> i64 {
    bytes_of(file) + bytes_of(&format!("{file}-wal"))
}

/// The rows behind the latency chart: one node's probe results over a window,
/// bucketed and in time order. Everything the chart draws is folded out of them
/// in [`close_bucket`].
///
/// The key is `(node_id, ts, task_id)`, so this is a seek and the rows emerge
/// sorted without a sorter, which is what allows the fold to hold one bucket at
/// a time. Asking SQLite for the summary instead cost three sorts of the whole
/// window -- two window passes and a GROUP BY -- against this single scan: on a
/// week of four probes, 284 ms against 54 ms, all of it holding the connection
/// the agents write through.
///
/// A constant because the query plan is asserted against it in
/// `rekeying_ping_record_keeps_the_rows_and_lets_the_chart_query_seek`.
const PING_ROWS: &str = "SELECT ts/?3, task_id, latency FROM ping_record
     WHERE node_id=?1 AND ts>=?2
           AND task_id IN (SELECT task_id FROM ping_node WHERE node_id=?1)
     ORDER BY ts";

// ---- proxy module: nodes, credentials, subscription customers ----

/// One proxy node = one sing-box inbound.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProxyNode {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub protocol: String,
    /// 0 means "allocate from the port pool" on create.
    #[serde(default)]
    pub listen_port: i64,
    #[serde(default)]
    pub sni: String,
    /// VLESS Reality flow: `xtls-rprx-vision` or empty for no flow.
    #[serde(default)]
    pub flow: String,
    /// Shadowsocks 的加密方法，例如 2022-blake3-aes-128-gcm；其余协议为空。
    #[serde(default)]
    pub method: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub remark: String,
    /// 节点所在服务器：0 = hub 本机，其余为 node 表的主键（M3 多机）。
    #[serde(default)]
    pub server_id: i64,
    /// 链式出口（M2.5）：空 = 直接出网，socks5 / http = 经上游代理出网。
    #[serde(default)]
    pub egress_type: String,
    #[serde(default)]
    pub egress_host: String,
    #[serde(default)]
    pub egress_port: i64,
    #[serde(default)]
    pub egress_username: String,
    #[serde(default)]
    pub egress_password: String,
    /// Request-only advanced fields. They are never read from a database row
    /// and are intentionally omitted from serialized API responses.
    #[serde(default, skip_serializing)]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing)]
    pub reality_private_key: Option<String>,
    #[serde(default, skip_serializing)]
    pub reality_short_id: Option<String>,
    /// 按协议限速（Mbps，0 = 不限）。tc 执行在 agent/hub 的 shaper 模块。
    #[serde(default)]
    pub rate_up: i64,
    #[serde(default)]
    pub rate_down: i64,
    /// 节点自有域名（切换主机功能）：非空时分享链接/二维码改用该域名，
    /// 换 IP/换主机不再换链接。需托管在 Cloudflare（dns.rs 仅此一家）。
    #[serde(default)]
    pub dns_name: String,
    /// 域名当前指向的机器 id（切换时更新）；与 server_id 可以不同——
    /// 切走后原机节点照跑，随时一键切回。
    #[serde(default)]
    pub dns_server_id: i64,
    /// A 记录最近同步的 IP（记账防打架，先例 node.dns_ip）。
    #[serde(default)]
    pub dns_ip: String,
    /// 镜像机（mirror_servers JSON，先例 relay_rules.entry_backups）：节点
    /// 额外渲染到的机器。身份参数单源——镜像机渲染的是同一套 uuid/密钥/
    /// 端口。仅由切换 API 追加、机器删除剔除；PUT 不接受客户端改写，
    /// 故不序列化。
    #[serde(default, skip_serializing)]
    pub mirror_servers: String,
}

/// Server-side TLS secrets a node's config and share links are built from.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProxySecret {
    #[serde(default)]
    pub node_id: i64,
    #[serde(default)]
    pub tls_mode: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
    /// 自签证书的 PEM，hysteria2 / anytls 的 selfsign 模式内联进配置。
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub key_pem: String,
    /// Shadowsocks-2022 多用户的服务器 PSK。
    #[serde(default)]
    pub psk: String,
}

/// One credential under a node's inbound. `sub_user_id` claims it for a
/// subscription customer; the customer's subscription embeds exactly this
/// credential, so two customers on one node never share one.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProxyUser {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub node_id: i64,
    pub name: String,
    pub credential: String,
    #[serde(default)]
    pub sub_user_id: Option<i64>,
    /// 凭据级到期（方向 40）：NULL=不启用，跟随客户级到期。
    #[serde(default)]
    pub expires_at: Option<String>,
    /// 凭据级流量配额（字节）：0=不启用。
    #[serde(default)]
    pub quota_bytes: i64,
    /// 分配给客户的时间（绑定时写入）；0=未分配或历史分配。
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub quota_used_up: i64,
    #[serde(default)]
    pub quota_used_down: i64,
    #[serde(default)]
    pub quota_period_start: i64,
    /// 月度重置跟随客户级的 quota_reset（''=一次性总量）。
    #[serde(default)]
    pub quota_reset: String,
}

/// 一条登录会话（安全页「登录会话」卡）：哈希只用于标识与踢除，token 本体不落库。
pub struct SessionRow {
    pub token_hash: String,
    pub expires_at: i64,
    pub ip: String,
    pub user_agent: String,
}

/// A subscription customer: owns a token, holds credentials via
/// `proxy_user.sub_user_id`.
///
/// M7 配额列：`quota_bytes` 0 = 不限；`quota_reset` `''` = 一次性总量包、
/// `'monthly'` = 自然月重置；`quota_used_up`/`quota_used_down` 是当期已累积
/// 的用户级用量（订阅响应按这两个数回传 subscription-userinfo），由记账
/// 链路增量维护；`quota_period_start` 标明当期从哪个自然月开始，跨月首次
/// 记账时连同用量一起清零。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SubUser {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub token: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub quota_bytes: i64,
    #[serde(default)]
    pub quota_reset: String,
    #[serde(default)]
    pub quota_used_up: i64,
    #[serde(default)]
    pub quota_used_down: i64,
    #[serde(default)]
    pub quota_period_start: i64,
    /// /u/{token} 用户中心页开关（默认开）。
    #[serde(default = "yes")]
    pub user_page: bool,
    /// 绑定的内容方案（sub_profiles.id）；NULL=未绑定，订阅回落裸节点输出。
    #[serde(default)]
    pub profile_id: Option<i64>,
    /// agent 分发开关：agent 机器可经分发端口回源本客户的订阅。
    #[serde(default)]
    pub agent_dist: bool,
    /// /u/ 用户中心页视图（overview 总览 / per_node 逐节点明细）。
    #[serde(default = "default_view_mode")]
    pub view_mode: String,
    /// 自助重置订阅开关（/u/ 页客户可自行轮换凭据+链接）。
    #[serde(default)]
    pub allow_self_reset: bool,
    /// 自助重置次数上限（用完须管理员处理；管理员重置不占次数）。
    #[serde(default = "default_reset_limit")]
    pub reset_limit: i64,
    /// 已自助重置次数。
    #[serde(default)]
    pub reset_count: i64,
    /// 上次自助重置时间（unix 秒）。
    #[serde(default)]
    pub last_reset_at: i64,
}

fn default_reset_limit() -> i64 {
    3
}

fn default_view_mode() -> String {
    "overview".into()
}

/// 一条 Realm 中转规则（M5）：中转机监听端口，把流量原样转发到落地地址。
/// M24 起支持多落地（relay_targets 子表）、每规则协议选择、负载均衡与
/// 加密隧道（transport/exit_* ——hub 同源渲染两端 realm.toml，参数天然配对）。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RelayRule {
    #[serde(default)]
    pub id: i64,
    /// 中转机：0 = hub 本机，其余为 node 表主键。
    #[serde(default)]
    pub server_id: i64,
    #[serde(default)]
    pub name: String,
    /// "21580" 或端口段 "20000-20100"（留空由服务端自动分配）。
    #[serde(default)]
    pub listen_port: String,
    /// 第一落地目标 "host:port"（relay_targets 的派生镜像，旧路径用）。
    #[serde(default)]
    pub target: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// 导入式规则的原始节点分享链接；手动规则为空。
    #[serde(default)]
    pub origin_link: String,
    #[serde(default)]
    pub created_at: i64,
    /// 每规则协议：both / tcp / udp。
    #[serde(default)]
    pub protocol: String,
    /// 规则备注。
    #[serde(default)]
    pub note: String,
    /// 负载均衡：'' / roundrobin / iphash。
    #[serde(default)]
    pub balance: String,
    /// 中转⇄落地加密层：'' / tls / ws / wss。
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub tls_sni: String,
    #[serde(default)]
    pub tls_insecure: bool,
    #[serde(default)]
    pub ws_path: String,
    /// 隧道落地机（>0 即隧道规则）与落地监听端口。
    #[serde(default)]
    pub exit_server_id: i64,
    #[serde(default)]
    pub exit_listen_port: String,
    /// 备用入口机（入口故障转移，二期）：JSON 数组的 node id。备用机的
    /// realm 渲染同一条入口腿（同端口→同目标），主入口双确认判挂后 DNS
    /// 翻转到备用机 IP。
    #[serde(default)]
    pub entry_backups: String,
    /// 高级绑定与协议头/多路径。
    #[serde(default)]
    pub listen_host: String,
    #[serde(default)]
    pub through: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub send_proxy: bool,
    #[serde(default)]
    pub mptcp: bool,
}

/// 中转规则的一个落地目标（M24）：多落地 + 负载均衡权重 + 健康状态。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RelayTarget {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub rule_id: i64,
    #[serde(default)]
    pub seq: i64,
    pub host: String,
    pub port: i64,
    #[serde(default = "one_i64")]
    pub weight: i64,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// up / down / unknown（纯 UDP 目标不探测）。
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub fail_streak: i64,
    #[serde(default)]
    pub ok_streak: i64,
    #[serde(default)]
    pub down_since: i64,
    #[serde(default)]
    pub last_checked: i64,
    /// 最近一次探测的 TCP connect 耗时（毫秒）；NULL = 未探到（down/超时）或未探测。
    #[serde(default)]
    pub last_latency_ms: Option<i64>,
}

fn one_i64() -> i64 {
    1
}

fn default_interval() -> i64 {
    60
}

/// 节点池节点：raw_link 与 clash_config 双形态至少存其一。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SubNode {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub raw_link: String,
    /// Clash 原生代理字段 JSON（yaml 导入零丢失形态）。
    #[serde(default)]
    pub clash_config: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub tags: Vec<String>,
    /// 来源外部订阅 URL（同步时按此整体替换）。
    #[serde(default)]
    pub source_url: String,
    /// 来源面板节点（import_managed 写入）；客户渲染时按它换用客户自有凭据。
    #[serde(default)]
    pub proxy_node_id: Option<i64>,
    #[serde(default)]
    pub note: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub latency_ms: i64,
    #[serde(default)]
    pub probed_at: i64,
    #[serde(default)]
    pub created_at: i64,
}

/// 外部订阅源（机场订阅 URL 实体化，支持定时同步与流量展示）。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SubSource {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default = "yes")]
    pub auto_update: bool,
    #[serde(default = "default_interval")]
    pub interval_min: i64,
    /// 上游 subscription-userinfo 原文。
    #[serde(default)]
    pub info: String,
    #[serde(default)]
    pub node_count: i64,
    #[serde(default)]
    pub last_sync: i64,
    #[serde(default)]
    pub created_at: i64,
}

/// 完整 Clash 配置模板（内容入库，随备份走）。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SubTemplate {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub is_builtin: bool,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub created_at: i64,
}

/// 规则模式自定义来源：模板来源（url 指向一份 ini/config）或类别集来源
/// （url 拉取或粘贴的妙妙屋 proxy-groups.json，data 存 normalize 后快照）。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RuleSource {
    #[serde(default)]
    pub id: i64,
    /// 'template' | 'categories'
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub last_sync: i64,
    #[serde(default)]
    pub created_at: i64,
}

fn row_to_rule_source(r: &rusqlite::Row) -> rusqlite::Result<RuleSource> {
    Ok(RuleSource {
        id: r.get("id")?,
        kind: r.get("kind")?,
        name: r.get("name")?,
        url: r.get("url")?,
        data: r.get("data")?,
        last_sync: r.get("last_sync")?,
        created_at: r.get("created_at")?,
    })
}

/// 命名规则片段：整段 YAML，按 kind 合并进生成配置的对应段。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SubSnippet {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    /// rules / dns
    #[serde(default)]
    pub kind: String,
    /// prepend / append（仅 rules）
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub content: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: i64,
}

/// 生成的订阅文件：模板绑定 + 标签勾选 + 片段勾选 + 有效期。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SubProfile {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub template_name: String,
    #[serde(default)]
    pub selected_tags: Vec<String>,
    #[serde(default)]
    pub snippet_ids: Vec<i64>,
    /// 0 = 永不过期；否则为过期时刻的 unix 秒。
    #[serde(default)]
    pub expires_at: i64,
    /// 组→有序成员的覆盖表（可视化拖拽分组）：成员 = 数字节点 id 或字符串
    /// 特殊项（DIRECT/组引用/占位符，渲染端直通或展开）。覆盖的组用这份列表
    /// 渲染，未覆盖的组仍走模板占位符自动展开。
    #[serde(default)]
    pub group_overrides: serde_json::Value,
    /// 勾选的分流类别 key 数组（非空 = 按类别动态生成，忽略 template_name）。
    #[serde(default)]
    pub selected_categories: Vec<String>,
    /// 勾选的节点 id 数组（非空 = 只包含这些节点）。
    #[serde(default)]
    pub selected_nodes: Vec<i64>,
    /// 静态订阅内容（非空 = 原样下发，忽略模板/类别/节点渲染）。
    #[serde(default)]
    pub static_content: String,
    /// agent 入口分发开关（agent 回源时 hub 校验）。
    #[serde(default)]
    pub agent_dist: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: i64,
}

fn row_to_sub_node(r: &rusqlite::Row) -> rusqlite::Result<SubNode> {
    let tags: String = r.get("tags")?;
    Ok(SubNode {
        id: r.get("id")?,
        name: r.get("name")?,
        raw_link: r.get("raw_link")?,
        clash_config: r.get("clash_config")?,
        protocol: r.get("protocol")?,
        server: r.get("server")?,
        port: r.get("port")?,
        tags: serde_json::from_str(&tags).unwrap_or_default(),
        source_url: r.get("source_url")?,
        note: r.get("note")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        latency_ms: r.get("latency_ms")?,
        probed_at: r.get("probed_at")?,
        created_at: r.get("created_at")?,
        proxy_node_id: r.get("proxy_node_id").ok().flatten(),
    })
}

fn row_to_sub_source(r: &rusqlite::Row) -> rusqlite::Result<SubSource> {
    Ok(SubSource {
        id: r.get("id")?,
        url: r.get("url")?,
        name: r.get("name")?,
        user_agent: r.get("user_agent")?,
        auto_update: r.get::<_, i64>("auto_update")? != 0,
        interval_min: r.get("interval_min")?,
        info: r.get("info")?,
        node_count: r.get("node_count")?,
        last_sync: r.get("last_sync")?,
        created_at: r.get("created_at")?,
    })
}

fn row_to_sub_template(r: &rusqlite::Row) -> rusqlite::Result<SubTemplate> {
    Ok(SubTemplate {
        id: r.get("id")?,
        name: r.get("name")?,
        note: r.get("note")?,
        is_builtin: r.get::<_, i64>("is_builtin")? != 0,
        content: r.get("content")?,
        created_at: r.get("created_at")?,
    })
}

fn row_to_sub_snippet(r: &rusqlite::Row) -> rusqlite::Result<SubSnippet> {
    Ok(SubSnippet {
        id: r.get("id")?,
        name: r.get("name")?,
        kind: r.get("kind")?,
        mode: r.get("mode")?,
        content: r.get("content")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        created_at: r.get("created_at")?,
    })
}

fn row_to_sub_profile(r: &rusqlite::Row) -> rusqlite::Result<SubProfile> {
    let tags: String = r.get("selected_tags")?;
    let snippets: String = r.get("snippet_ids")?;
    let overrides: String = r.get("group_overrides").unwrap_or_default();
    let categories: String = r.get("selected_categories").unwrap_or_default();
    let sel_nodes: String = r.get("selected_nodes").unwrap_or_default();
    let static_content: String = r.get("static_content").unwrap_or_default();
    let agent_dist: i64 = r.get("agent_dist").unwrap_or(0);
    Ok(SubProfile {
        id: r.get("id")?,
        name: r.get("name")?,
        token: r.get("token")?,
        template_name: r.get("template_name")?,
        selected_tags: serde_json::from_str(&tags).unwrap_or_default(),
        snippet_ids: serde_json::from_str(&snippets).unwrap_or_default(),
        group_overrides: serde_json::from_str(&overrides).unwrap_or_else(|_| serde_json::json!({})),
        selected_categories: serde_json::from_str(&categories).unwrap_or_default(),
        selected_nodes: serde_json::from_str(&sel_nodes).unwrap_or_default(),
        static_content,
        agent_dist: agent_dist != 0,
        expires_at: r.get("expires_at")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        created_at: r.get("created_at")?,
    })
}

fn row_to_relay_rule(r: &rusqlite::Row) -> rusqlite::Result<RelayRule> {
    Ok(RelayRule {
        id: r.get("id")?,
        server_id: r.get("server_id")?,
        name: r.get("name")?,
        listen_port: r.get("listen_port")?,
        target: r.get("target")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        origin_link: r.get("origin_link").unwrap_or_default(),
        created_at: r.get("created_at")?,
        protocol: r.get("protocol").unwrap_or_default(),
        note: r.get("note").unwrap_or_default(),
        balance: r.get("balance").unwrap_or_default(),
        transport: r.get("transport").unwrap_or_default(),
        tls_sni: r.get("tls_sni").unwrap_or_default(),
        tls_insecure: r.get::<_, Option<i64>>("tls_insecure").unwrap_or_default().unwrap_or(0) != 0,
        ws_path: r.get("ws_path").unwrap_or_default(),
        exit_server_id: r.get("exit_server_id").unwrap_or_default(),
        exit_listen_port: r.get("exit_listen_port").unwrap_or_default(),
        listen_host: r.get("listen_host").unwrap_or_default(),
        through: r.get("through").unwrap_or_default(),
        interface: r.get("interface").unwrap_or_default(),
        send_proxy: r.get::<_, Option<i64>>("send_proxy").unwrap_or_default().unwrap_or(0) != 0,
        mptcp: r.get::<_, Option<i64>>("mptcp").unwrap_or_default().unwrap_or(0) != 0,
        entry_backups: r.get("entry_backups").unwrap_or_default(),
    })
}

fn row_to_relay_target(r: &rusqlite::Row) -> rusqlite::Result<RelayTarget> {
    Ok(RelayTarget {
        id: r.get("id")?,
        rule_id: r.get("rule_id")?,
        seq: r.get("seq")?,
        host: r.get("host")?,
        port: r.get("port")?,
        weight: r.get("weight")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        state: r.get("state")?,
        fail_streak: r.get("fail_streak")?,
        ok_streak: r.get("ok_streak")?,
        down_since: r.get("down_since")?,
        last_checked: r.get("last_checked")?,
        last_latency_ms: r.get("last_latency_ms").ok().flatten(),
    })
}

/// A node together with everything its config and links are rendered from.
#[derive(Debug, Clone, Default)]
pub struct NodeBundle {
    pub node: ProxyNode,
    pub secret: ProxySecret,
    pub users: Vec<ProxyUser>,
}

fn row_to_proxy_node(r: &rusqlite::Row) -> rusqlite::Result<ProxyNode> {
    Ok(ProxyNode {
        id: r.get("id")?,
        name: r.get("name")?,
        protocol: r.get("protocol")?,
        listen_port: r.get("listen_port")?,
        sni: r.get("sni")?,
        flow: r.get("flow")?,
        method: r.get("method")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        remark: r.get("remark")?,
        server_id: r.get("server_id")?,
        egress_type: r.get("egress_type")?,
        egress_host: r.get("egress_host")?,
        egress_port: r.get("egress_port")?,
        egress_username: r.get("egress_username")?,
        egress_password: r.get("egress_password")?,
        rate_up: r.get("rate_up")?,
        rate_down: r.get("rate_down")?,
        dns_name: r.get("dns_name")?,
        dns_server_id: r.get("dns_server_id")?,
        dns_ip: r.get("dns_ip")?,
        mirror_servers: r.get("mirror_servers")?,
        uuid: None,
        reality_private_key: None,
        reality_short_id: None,
    })
}

fn row_to_proxy_secret(r: &rusqlite::Row) -> rusqlite::Result<ProxySecret> {
    Ok(ProxySecret {
        node_id: r.get("node_id")?,
        tls_mode: r.get("tls_mode")?,
        private_key: r.get("private_key")?,
        public_key: r.get("public_key")?,
        short_id: r.get("short_id")?,
        cert_pem: r.get("cert_pem")?,
        key_pem: r.get("key_pem")?,
        psk: r.get("psk")?,
    })
}

fn row_to_proxy_user(r: &rusqlite::Row) -> rusqlite::Result<ProxyUser> {
    Ok(ProxyUser {
        id: r.get("id")?,
        node_id: r.get("node_id")?,
        name: r.get("name")?,
        credential: r.get("credential")?,
        sub_user_id: r.get("sub_user_id")?,
        expires_at: r.get("expires_at").ok().flatten(),
        quota_bytes: r.get("quota_bytes").unwrap_or(0),
        created_at: r.get("created_at").unwrap_or(0),
        quota_used_up: r.get("quota_used_up").unwrap_or(0),
        quota_used_down: r.get("quota_used_down").unwrap_or(0),
        quota_period_start: r.get("quota_period_start").unwrap_or(0),
        quota_reset: r.get("quota_reset").unwrap_or_default(),
    })
}

fn row_to_sub_user(r: &rusqlite::Row) -> rusqlite::Result<SubUser> {
    Ok(SubUser {
        id: r.get("id")?,
        name: r.get("name")?,
        token: r.get("token")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        expires_at: r.get("expires_at")?,
        remark: r.get("remark")?,
        created_at: r.get("created_at")?,
        quota_bytes: r.get("quota_bytes")?,
        quota_reset: r.get("quota_reset")?,
        quota_used_up: r.get("quota_used_up")?,
        quota_used_down: r.get("quota_used_down")?,
        quota_period_start: r.get("quota_period_start")?,
        user_page: r.get::<_, Option<i64>>("user_page").unwrap_or(Some(1)).unwrap_or(1) != 0,
        profile_id: r.get("profile_id").ok().flatten(),
        agent_dist: r.get::<_, Option<i64>>("agent_dist").ok().flatten().unwrap_or(0) != 0,
        view_mode: r.get("view_mode").unwrap_or_else(|_| "overview".into()),
        allow_self_reset: r.get::<_, Option<i64>>("allow_self_reset").ok().flatten().unwrap_or(0) != 0,
        reset_limit: r.get::<_, Option<i64>>("reset_limit").ok().flatten().unwrap_or(3),
        reset_count: r.get::<_, Option<i64>>("reset_count").ok().flatten().unwrap_or(0),
        last_reset_at: r.get::<_, Option<i64>>("last_reset_at").ok().flatten().unwrap_or(0),
    })
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        // Queried before CREATE TABLE runs: a file with no tables receives the
        // current schema and then the full migration history, so tables born
        // in `migrate_to_N` exist here exactly as they do on an upgraded file.
        let fresh = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table'", [], |r| r.get::<_, i64>(0))?
            == 0;
        conn.execute_batch(SCHEMA)?;
        restrict(path);

        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        migrate(&conn, if fresh { 0 } else { version })?;
        Ok(Self(Mutex::new(conn)))
    }

    fn conn(&self) -> ConnGuard<'_> {
        let db = self as *const Db as usize;
        if CONN_HELD.with(|held| held.borrow().contains(&db)) {
            // 与其同一 Db 重入后静默永久冻死（生产曾需 SIGKILL），不如当场炸：
            // dev/test 立即给出重入点；release panic=abort 退出后 systemd 3s 拉起。
            panic!("Db::conn 同线程重入：同一 Db 的守卫存活期间再取锁必死锁，回溯调用链找持有中的守卫");
        }
        CONN_HELD.with(|held| held.borrow_mut().push(db));
        ConnGuard { guard: self.0.lock().unwrap_or_else(|e| e.into_inner()), db }
    }

    // ---- settings ----

    pub fn get(&self, key: &str) -> Option<String> {
        self.lookup(key).ok().flatten()
    }

    /// As [`Db::get`], with a failed read kept apart from an absent key, for a
    /// caller that would otherwise act on "nothing saved".
    pub fn lookup(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row("SELECT value FROM setting WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO setting (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ---- 通知渠道与路由（二期底座）----

    pub fn notify_channels(&self) -> Result<Vec<NotifyChannel>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, name, kind, config, enabled, created_at FROM notify_channels ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(NotifyChannel {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                config: r.get(3)?,
                enabled: r.get::<_, i64>(4)? != 0,
                created_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn notify_channel(&self, id: i64) -> Result<Option<NotifyChannel>> {
        Ok(self.notify_channels()?.into_iter().find(|c| c.id == id))
    }

    /// 渠道名唯一，撞名返回 None 交由调用方报错。
    pub fn create_notify_channel(&self, name: &str, kind: &str, config: &str) -> Result<Option<i64>> {
        let exists: bool = self.conn().query_row(
            "SELECT COUNT(*) > 0 FROM notify_channels WHERE name = ?1",
            [name],
            |r| r.get(0),
        )?;
        if exists {
            return Ok(None);
        }
        self.conn().execute(
            "INSERT INTO notify_channels (name, kind, config, enabled, created_at)
             VALUES (?1, ?2, ?3, 1, strftime('%s','now'))",
            params![name, kind, config],
        )?;
        Ok(Some(self.conn().last_insert_rowid()))
    }

    pub fn update_notify_channel(&self, id: i64, name: &str, config: &str, enabled: bool) -> Result<bool> {
        let name_taken: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM notify_channels WHERE name = ?1 AND id <> ?2",
                params![name, id],
                |r| r.get(0),
            )
            .optional()?;
        if name_taken.is_some() {
            return Ok(false);
        }
        let changed = self.conn().execute(
            "UPDATE notify_channels SET name = ?2, config = ?3, enabled = ?4 WHERE id = ?1",
            params![id, name, config, enabled as i64],
        )?;
        Ok(changed > 0)
    }

    /// 删除渠道并从所有路由里摘除（引用悬空的渠道 id 在路由解析时跳过）。
    pub fn delete_notify_channel(&self, id: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM notify_channels WHERE id = ?1", [id])?;
        let mut stmt = tx.prepare("SELECT event, channels FROM notify_routes")?;
        let rows: Vec<(String, String)> =
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?;
        drop(stmt);
        for (event, channels) in rows {
            let Ok(mut ids) = serde_json::from_str::<Vec<i64>>(&channels) else { continue };
            let before = ids.len();
            ids.retain(|v| *v != id);
            if ids.len() != before {
                tx.execute(
                    "UPDATE notify_routes SET channels = ?2 WHERE event = ?1",
                    params![event, serde_json::to_string(&ids)?],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// 每类事件路由到的渠道 id。没有行的事件回落「全部启用渠道」（迁移只为
    /// 已配渠道时物化，将来新增事件类型无需迁移）。
    pub fn notify_routes(&self) -> Result<Vec<(String, Vec<i64>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT event, channels FROM notify_routes ORDER BY event")?;
        let rows = stmt.query_map([], |r| {
            let event: String = r.get(0)?;
            let channels: String = r.get(1)?;
            Ok((event, serde_json::from_str(&channels).unwrap_or_default()))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn set_notify_route(&self, event: &str, ids: &[i64]) -> Result<()> {
        self.conn().execute(
            "INSERT INTO notify_routes (event, channels) VALUES (?1, ?2)
             ON CONFLICT(event) DO UPDATE SET channels = excluded.channels",
            params![event, serde_json::to_string(ids)?],
        )?;
        Ok(())
    }

    // ---- proxy nodes ----

    pub fn proxy_nodes(&self) -> Result<Vec<ProxyNode>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM proxy_node ORDER BY id")?;
        let rows = stmt.query_map([], row_to_proxy_node)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn proxy_node(&self, id: i64) -> Result<Option<ProxyNode>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM proxy_node WHERE id = ?1", [id], row_to_proxy_node)
            .optional()?)
    }

    /// Every node with its secret and credentials, in id order. Config
    /// rendering and subscription rendering both start here.
    pub fn proxy_node_bundles(&self) -> Result<Vec<NodeBundle>> {
        let conn = self.conn();
        let mut out = Vec::new();
        let mut stmt = conn.prepare("SELECT * FROM proxy_node ORDER BY id")?;
        let nodes = stmt.query_map([], row_to_proxy_node)?.collect::<Result<Vec<_>, _>>()?;
        for node in nodes {
            let secret = conn
                .query_row("SELECT * FROM proxy_secret WHERE node_id = ?1", [node.id], row_to_proxy_secret)
                .optional()?
                .unwrap_or_default();
            let mut users = conn.prepare("SELECT * FROM proxy_user WHERE node_id = ?1 ORDER BY id")?;
            let users = users.query_map([node.id], row_to_proxy_user)?.collect::<Result<Vec<_>, _>>()?;
            out.push(NodeBundle { node, secret, users });
        }
        Ok(out)
    }

    /// Ports already taken by proxy nodes on one server. Uniqueness is per
    /// machine: two servers can both listen on 20000.
    pub fn proxy_used_ports(&self, server_id: i64) -> Result<Vec<i64>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT listen_port FROM proxy_node WHERE server_id = ?1")?;
        let rows = stmt.query_map([server_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Creates a node with its secret and a default credential, returning the
    /// node id. One transaction: a node without a secret cannot render.
    pub fn create_proxy_node(&self, n: &ProxyNode, secret: &ProxySecret, credential: &str) -> Result<i64> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let created = Utc::now().timestamp();
        let node_id = match tx.execute(
            "INSERT INTO proxy_node (name, protocol, listen_port, sni, flow, method, enabled, remark, created_at,
                                      server_id, egress_type, egress_host, egress_port, egress_username, egress_password,
                                      rate_up, rate_down, dns_name, dns_server_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?10)",
            params![n.name, n.protocol, n.listen_port, n.sni, n.flow, n.method, n.enabled as i64, n.remark, created,
                    n.server_id, n.egress_type, n.egress_host, n.egress_port, n.egress_username, n.egress_password,
                    n.rate_up, n.rate_down, n.dns_name.trim()],
        ) {
            Ok(_) => tx.last_insert_rowid(),
            Err(e) if e.to_string().contains("UNIQUE constraint failed") => {
                return Err(anyhow::Error::msg(crate::Shown(format!("端口 {} 已被占用", n.listen_port))))
            }
            Err(e) => return Err(e.into()),
        };
        tx.execute(
            "INSERT INTO proxy_secret (node_id, tls_mode, private_key, public_key, short_id, cert_pem, key_pem, psk)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![node_id, secret.tls_mode, secret.private_key, secret.public_key, secret.short_id, secret.cert_pem, secret.key_pem, secret.psk],
        )?;
        tx.execute(
            "INSERT INTO proxy_user (node_id, name, credential) VALUES (?1,?2,?3)",
            params![node_id, "default", credential],
        )?;
        tx.commit()?;
        Ok(node_id)
    }

    /// Updates the mutable fields of a node. The port's uniqueness is enforced
    /// by the schema; the friendly wording is applied by the caller, which
    /// checks the pool first.
    pub fn update_proxy_node(
        &self,
        n: &ProxyNode,
        secret: Option<&ProxySecret>,
        credential: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let old = tx
            .query_row(
                "SELECT server_id, listen_port, dns_server_id, mirror_servers FROM proxy_node WHERE id = ?1",
                [n.id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let res = tx.execute(
            "UPDATE proxy_node SET name=?2, protocol=?3, listen_port=?4, sni=?5, flow=?6, method=?7, enabled=?8, remark=?9,
                                   server_id=?10, egress_type=?11, egress_host=?12, egress_port=?13, egress_username=?14, egress_password=?15,
                                   rate_up=?16, rate_down=?17, dns_name=?18
             WHERE id=?1",
            params![n.id, n.name, n.protocol, n.listen_port, n.sni, n.flow, n.method, n.enabled as i64, n.remark,
                    n.server_id, n.egress_type, n.egress_host, n.egress_port, n.egress_username, n.egress_password,
                    n.rate_up, n.rate_down, n.dns_name.trim()],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("节点不存在，可能已被删除".into())));
        }
        // 机器迁移时域名指向跟随原机（未切换过时指向=原机）。
        if let Some((old_server, _, old_dns_server, _)) = old.as_ref() {
            if old_server != &n.server_id && old_dns_server == old_server {
                tx.execute(
                    "UPDATE proxy_node SET dns_server_id = ?2 WHERE id = ?1",
                    params![n.id, n.server_id],
                )?;
            }
        }
        // 采样与连接日志以 server_id + in-{端口} 为键。端口/服务器变更时把
        // 历史行改到新键——否则它们以「节点可能已删除」残留、日志页的节点
        // 筛选也失配。新键不可能有别人的行：端口按服务器唯一，且节点删除时
        // 已带走自己的行。镜像机上的同节点行一并改（节点在每台机各一组键）。
        if let Some((old_server, old_port, _, old_mirrors)) = old {
            if old_server != n.server_id || old_port != n.listen_port {
                let to = format!("in-{}", n.listen_port);
                let from = format!("in-{old_port}");
                let mut machines = vec![old_server];
                machines.extend(serde_json::from_str::<Vec<i64>>(old_mirrors.trim()).unwrap_or_default());
                for sid in machines {
                    tx.execute(
                        "UPDATE traffic_samples SET server_id = ?1, node_tag = ?2 WHERE server_id = ?3 AND node_tag = ?4",
                        params![n.server_id, to, sid, from],
                    )?;
                    // OR IGNORE：极端情况下 conn_id 跨机撞车时保留原行，不挡节点更新。
                    tx.execute(
                        "UPDATE OR IGNORE connection_log SET server_id = ?1, inbound = ?2 WHERE server_id = ?3 AND inbound = ?4",
                        params![n.server_id, to, sid, from],
                    )?;
                }
            }
        }
        if let Some(s) = secret {
            tx.execute(
                "UPDATE proxy_secret SET private_key=?2, public_key=?3, short_id=?4 WHERE node_id=?1",
                params![n.id, s.private_key, s.public_key, s.short_id],
            )?;
        }
        if let Some(c) = credential {
            tx.execute(
                "UPDATE proxy_user SET credential=?2 WHERE node_id=?1 AND name='default'",
                params![n.id, c],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_proxy_node(&self, id: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // Proxy traffic samples historically use `server_id + in-{port}` as
        // their key. Remove those samples with the node so a later node that
        // reuses the port starts with a fresh history. Mirror machines carry
        // the same tag under their own server_id — sweep them too.
        let identity = tx
            .query_row(
                "SELECT server_id, listen_port, mirror_servers FROM proxy_node WHERE id = ?1",
                [id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)),
            )
            .optional()?;
        if let Some((server_id, listen_port, mirrors)) = identity {
            let tag = format!("in-{listen_port}");
            let mut machines = vec![server_id];
            machines.extend(serde_json::from_str::<Vec<i64>>(mirrors.trim()).unwrap_or_default());
            for sid in machines {
                tx.execute(
                    "DELETE FROM traffic_samples WHERE server_id = ?1 AND node_tag = ?2",
                    params![sid, tag],
                )?;
            }
        }
        tx.execute("DELETE FROM proxy_node WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn proxy_secret(&self, node_id: i64) -> Result<Option<ProxySecret>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM proxy_secret WHERE node_id = ?1", [node_id], row_to_proxy_secret)
            .optional()?)
    }

    pub fn proxy_default_credential(&self, node_id: i64) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT credential FROM proxy_user WHERE node_id = ?1 AND name = 'default' LIMIT 1",
                [node_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Replaces a node's self-signed certificate, used when the SNI it was
    /// minted for changes.
    pub fn update_proxy_secret_cert(&self, node_id: i64, cert_pem: &str, key_pem: &str) -> Result<()> {
        let res = self.conn().execute(
            "UPDATE proxy_secret SET cert_pem = ?2, key_pem = ?3 WHERE node_id = ?1",
            params![node_id, cert_pem, key_pem],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("节点不存在，可能已被删除".into())));
        }
        Ok(())
    }

    // ---- 切换主机（mirror_servers / dns_server_id）----

    /// 节点渲染到的机器全集（含镜像机）。proxy.rs 的渲染过滤与端口占用
    /// 都以它为准。
    pub fn proxy_node_mirrors(&self, node_id: i64) -> Result<Vec<i64>> {
        Ok(self
            .conn()
            .query_row("SELECT mirror_servers FROM proxy_node WHERE id = ?1", [node_id], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .and_then(|s| serde_json::from_str::<Vec<i64>>(s.trim()).ok())
            .unwrap_or_default())
    }

    /// 切换主机：把 server_id 追加进镜像集（已在不重复加）。幂等。
    pub fn add_proxy_node_mirror(&self, node_id: i64, server_id: i64) -> Result<()> {
        let conn = self.conn();
        let Some(n) = conn
            .query_row("SELECT server_id, mirror_servers FROM proxy_node WHERE id = ?1", [node_id], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .optional()?
        else {
            return Err(anyhow::Error::msg(crate::Shown("节点不存在，可能已被删除".into())));
        };
        let mut mirrors = serde_json::from_str::<Vec<i64>>(n.1.trim()).unwrap_or_default();
        if n.0 == server_id || mirrors.contains(&server_id) {
            return Ok(());
        }
        mirrors.push(server_id);
        conn.execute(
            "UPDATE proxy_node SET mirror_servers = ?2 WHERE id = ?1",
            params![node_id, serde_json::to_string(&mirrors)?],
        )?;
        Ok(())
    }

    /// 机器删除：从所有节点的镜像集剔除该机。域名指向不自动改——
    /// 由管理员在面板上自行切换。
    pub fn strip_server_from_mirrors(&self, server_id: i64) -> Result<()> {
        // 先取快照再拿连接锁：conn() 的 Mutex 非重入，握着锁再调
        // proxy_nodes()（内部也取锁）会自死锁。
        let updates: Vec<(i64, String)> = self
            .proxy_nodes()?
            .into_iter()
            .filter_map(|n| {
                let mut mirrors =
                    serde_json::from_str::<Vec<i64>>(n.mirror_servers.trim()).unwrap_or_default();
                if mirrors.contains(&server_id) {
                    mirrors.retain(|m| *m != server_id);
                    Some((n.id, serde_json::to_string(&mirrors).ok()?))
                } else {
                    None
                }
            })
            .collect();
        let conn = self.conn();
        for (id, json) in updates {
            conn.execute("UPDATE proxy_node SET mirror_servers = ?2 WHERE id = ?1", params![id, json])?;
        }
        Ok(())
    }

    /// 切换主机落地：域名指向 + A 记录记账一次写入。
    pub fn set_proxy_dns_target(&self, node_id: i64, server_id: i64, ip: &str) -> Result<()> {
        let res = self.conn().execute(
            "UPDATE proxy_node SET dns_server_id = ?2, dns_ip = ?3 WHERE id = ?1",
            params![node_id, server_id, ip],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("节点不存在，可能已被删除".into())));
        }
        Ok(())
    }

    /// A 记录记账（DDNS 跟随用），不动指向。
    pub fn update_proxy_dns_ip(&self, node_id: i64, ip: &str) -> Result<()> {
        self.conn().execute("UPDATE proxy_node SET dns_ip = ?2 WHERE id = ?1", params![node_id, ip])?;
        Ok(())
    }

    // ---- proxy credentials ----

    pub fn create_proxy_user(&self, node_id: i64, name: &str, credential: &str) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO proxy_user (node_id, name, credential) VALUES (?1,?2,?3)",
            params![node_id, name, credential],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn delete_proxy_user(&self, id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM proxy_user WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Claims or releases a credential for a subscription customer. Deleting
    /// the customer happens through `delete_sub_user`, which clears these
    /// first so no credential keeps pointing at a ghost.
    pub fn set_proxy_user_sub(&self, id: i64, sub_user_id: Option<i64>) -> Result<()> {
        // 绑定即分配：分配时间只在绑定时写入，解绑保留（导出口径=归属该客户的时间）。
        let res = self.conn().execute(
            "UPDATE proxy_user SET sub_user_id = ?2,
                                   created_at = CASE WHEN ?2 IS NOT NULL THEN ?3 ELSE created_at END
             WHERE id = ?1",
            params![id, sub_user_id, Utc::now().timestamp()],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("凭据不存在，可能已被删除".into())));
        }
        Ok(())
    }

    // ---- subscription customers ----

    pub fn sub_users(&self) -> Result<Vec<SubUser>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM sub_user ORDER BY id")?;
        let rows = stmt.query_map([], row_to_sub_user)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn sub_user(&self, id: i64) -> Result<Option<SubUser>> {
        Ok(self.conn().query_row("SELECT * FROM sub_user WHERE id = ?1", [id], row_to_sub_user).optional()?)
    }

    pub fn sub_user_by_token(&self, token: &str) -> Result<Option<SubUser>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM sub_user WHERE token = ?1", [token], row_to_sub_user)
            .optional()?)
    }

    pub fn create_sub_user(&self, name: &str, token: &str) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO sub_user (name, token, created_at) VALUES (?1,?2,?3)",
            params![name, token, Utc::now().timestamp()],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// 凭据级限额/到期（方向三）：保存 分配关系 上的 到期日期与流量配额。
    #[allow(clippy::too_many_arguments)]
    pub fn set_proxy_user_limits(
        &self,
        id: i64,
        expires_at: Option<String>,
        quota_bytes: i64,
        quota_reset: &str,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE proxy_user SET expires_at=?2, quota_bytes=?3, quota_used_up=0, quota_used_down=0,
             quota_period_start=CASE WHEN ?5 = 'monthly' THEN ?6 ELSE 0 END, quota_reset=?5 WHERE id=?1",
            params![id, expires_at, quota_bytes.max(0), quota_reset, quota_reset, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    /// 客户的 /u/ 视图模式（overview 总览 / per_node 逐节点明细）。
    /// 自助重置配置（管理端）：开关与次数上限。
    pub fn set_sub_user_self_reset(&self, id: i64, allow: bool, limit: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE sub_user SET allow_self_reset = ?2, reset_limit = ?3 WHERE id = ?1",
            params![id, allow as i64, limit.max(0)],
        )?;
        Ok(())
    }

    /// 记录一次自助重置（计数 +1、写时间）。
    pub fn record_self_reset(&self, id: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE sub_user SET reset_count = reset_count + 1, last_reset_at = ?2 WHERE id = ?1",
            params![id, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    /// 轮换凭据值（自助/管理端重置）：原行原名，只换秘密值，计量历史不断。
    pub fn update_proxy_user_credential(&self, id: i64, credential: &str) -> Result<()> {
        self.conn()
            .execute("UPDATE proxy_user SET credential = ?2 WHERE id = ?1", params![id, credential])?;
        Ok(())
    }

    pub fn set_sub_user_view_mode(&self, id: i64, mode: &str) -> Result<()> {
        self.conn().execute("UPDATE sub_user SET view_mode = ?2 WHERE id = ?1", params![id, mode])?;
        Ok(())
    }

    /// 每凭据流量记账（方向三）：跨月重置跟随客户级 quota_reset（客户月度则
    /// 凭据同步跨月清零）；返回 刚越过自身配额的 proxy_user id（调用方即时
    /// 推向摘除）。
    pub fn bump_proxy_user_usage(&self, deltas: &[(i64, i64, i64)]) -> Result<Vec<i64>> {
        if deltas.is_empty() {
            return Ok(Vec::new());
        }
        let _month_start = Local::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut crossed = Vec::new();
        for (pu_id, uplink, downlink) in deltas {
            // 凭据级不设独立重置周期：客户级跨月清零时同批清零（见 bump_sub_usage
            // 的 fresh 分支），这里只累加并检测越过自身配额的边沿。
            let (used, quota): (i64, i64) = tx.query_row(
                "SELECT quota_used_up + quota_used_down, quota_bytes FROM proxy_user WHERE id = ?1",
                [pu_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if quota <= 0 {
                continue;
            }
            let now_used = used + uplink + downlink;
            tx.execute(
                "UPDATE proxy_user SET quota_used_up = quota_used_up + ?2, quota_used_down = quota_used_down + ?3 WHERE id = ?1",
                params![pu_id, uplink, downlink],
            )?;
            if used < quota && now_used >= quota {
                crossed.push(*pu_id);
            }
        }
        tx.commit()?;
        Ok(crossed)
    }

    /// 建客户并可选绑定内容方案（方向二：新建时即可选方案）。
    pub fn create_sub_user_full(&self, name: &str, token: &str, profile_id: Option<i64>) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO sub_user (name, token, created_at, profile_id) VALUES (?1,?2,?3,?4)",
            params![name, token, Utc::now().timestamp(), profile_id],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// 保存客户资料。name/quota_reset 已由调用方校验，这里只落库；用量
    /// （quota_used_up/down/quota_period_start）归记账链路，保存不改写。
    /// 用户中心页开关（/u/{token} 页面访问）。
    pub fn set_sub_user_page(&self, id: i64, on: bool) -> Result<()> {
        self.conn().execute("UPDATE sub_user SET user_page = ?2 WHERE id = ?1", params![id, on as i64])?;
        Ok(())
    }

    pub fn update_sub_user(&self, id: i64, s: &SubUser) -> Result<()> {
        let res = self.conn().execute(
            "UPDATE sub_user SET name=?2, enabled=?3, expires_at=?4, remark=?5,
             quota_bytes=?6, quota_reset=?7, profile_id=?8, view_mode=?9 WHERE id=?1",
            params![
                id,
                s.name,
                s.enabled as i64,
                s.expires_at,
                s.remark,
                s.quota_bytes,
                s.quota_reset,
                s.profile_id,
                if s.view_mode.is_empty() { "overview" } else { &s.view_mode }
            ],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("订阅客户不存在，可能已被删除".into())));
        }
        Ok(())
    }

    /// 客户的 agent 分发开关（分发端口按它门控回源）。
    pub fn set_sub_user_agent_dist(&self, id: i64, on: bool) -> Result<()> {
        self.conn().execute("UPDATE sub_user SET agent_dist = ?2 WHERE id = ?1", params![id, on as i64])?;
        Ok(())
    }

    /// 记账链路把一批用户级增量记到各自客户头上，返回这批增量里刚刚越过
    /// 自身配额的客户 id（记账前未超、记账后已超的边沿），调用方据此立即
    /// 触发摘除，不等下一轮心跳对账。跨入新自然月（quota_reset = 'monthly'）
    /// 的首次记账把当期清零重计；一次性总量包从不清零。未知用户名（凭据刚
    /// 被删除的竞态）静默丢弃，与节点级采样对已删节点的处理一致。
    pub fn bump_sub_usage(&self, deltas: &[(i64, i64, i64)]) -> Result<Vec<i64>> {
        if deltas.is_empty() {
            return Ok(Vec::new());
        }
        let month_start = Local::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut crossed = Vec::new();
        for (sub_id, uplink, downlink) in deltas {
            let (reset, period_start, quota, used): (String, i64, i64, i64) = tx.query_row(
                "SELECT quota_reset, quota_period_start, quota_bytes, quota_used_up + quota_used_down FROM sub_user WHERE id = ?1",
                [sub_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            let fresh = reset == "monthly" && period_start < month_start;
            if fresh {
                tx.execute(
                    "UPDATE sub_user SET quota_used_up = ?2, quota_used_down = ?3, quota_period_start = ?4 WHERE id = ?1",
                    params![sub_id, uplink, downlink, month_start],
                )?;
                // 凭据级配额跟随客户跨月清零（方向 40）
                tx.execute(
                    "UPDATE proxy_user SET quota_used_up = 0, quota_used_down = 0, quota_period_start = ?2 WHERE sub_user_id = ?1",
                    params![sub_id, month_start],
                )?;
            } else {
                tx.execute(
                    "UPDATE sub_user SET quota_used_up = quota_used_up + ?2, quota_used_down = quota_used_down + ?3 WHERE id = ?1",
                    params![sub_id, uplink, downlink],
                )?;
            }
            let now_used = if fresh { uplink + downlink } else { used + uplink + downlink };
            if quota > 0 && used < quota && now_used >= quota {
                crossed.push(*sub_id);
            }
            // 小时汇总（概览客户排行的窗口数据源）：同一事务里按整点桶增量。
            let bucket = (Utc::now().timestamp() / 3600) * 3600;
            tx.execute(
                "INSERT INTO sub_usage_hourly (sub_user_id, bucket, up, down) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(sub_user_id, bucket) DO UPDATE SET up = up + ?3, down = down + ?4",
                params![sub_id, bucket, uplink, downlink],
            )?;
        }
        tx.commit()?;
        Ok(crossed)
    }

    /// 概览客户排行（按窗口）：sub_usage_hourly 在 [since, ∞) 的每客户用量，
    /// 按总量降序前 10。返回 (sub_user_id, up, down)，名字/配额由调用方映射。
    /// 桶是整点对齐的，窗口起点所在的那个桶整桶计入（≤1h 粒度误差，与走势
    /// 图同宽容度）。
    pub fn sub_usage_rank(&self, since: i64) -> Result<Vec<(i64, i64, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT sub_user_id, COALESCE(SUM(up),0), COALESCE(SUM(down),0)
             FROM sub_usage_hourly WHERE bucket >= ?1
             GROUP BY sub_user_id ORDER BY SUM(up)+SUM(down) DESC LIMIT 10",
        )?;
        let rows = stmt.query_map([since], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 小时汇总的保留清理：最大概览窗口 30 天 + 余量。
    pub fn prune_sub_usage_hourly(&self, keep_days: i64) -> Result<usize> {
        let cutoff = Utc::now().timestamp() - keep_days * 86_400;
        let conn = self.conn();
        Ok(conn.execute("DELETE FROM sub_usage_hourly WHERE bucket < ?1", [cutoff])?)
    }

    /// 一个客户凭据所在的所有服务器，生命周期变化后按它定向触发 reconcile。
    /// 凭据（proxy_user id）所在节点的 server_id（凭据级越额推送用）。
    pub fn proxy_server_of_user(&self, pu_id: i64) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT n.server_id FROM proxy_user u JOIN proxy_node n ON n.id = u.node_id WHERE u.id = ?1",
                [pu_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn proxy_servers_of_sub(&self, sub_id: i64) -> Result<Vec<i64>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT n.server_id, n.mirror_servers FROM proxy_user u
             JOIN proxy_node n ON n.id = u.node_id WHERE u.sub_user_id = ?1",
        )?;
        let rows = stmt.query_map([sub_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        // 镜像机一并返回：客户凭据的摘除要推到该节点的每一台机器。
        let mut set = std::collections::BTreeSet::new();
        for row in rows {
            let (server_id, mirrors) = row?;
            set.insert(server_id);
            for m in serde_json::from_str::<Vec<i64>>(mirrors.trim()).unwrap_or_default() {
                set.insert(m);
            }
        }
        Ok(set.into_iter().collect())
    }

    /// 一台服务器上凭据用户名 → 所属客户的映射，用户级流量记账用。同一
    /// 服务器的用户名必须唯一（v2ray 计数器按名字聚合，重名会合并用量），
    /// 创建入口已保证；这里重名取先者，旧行为兜底。
    pub fn proxy_sub_of_names(&self, server_id: i64, names: &[String]) -> Result<Vec<(String, Option<i64>)>> {
        let conn = self.conn();
        let mut out = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT u.name, u.sub_user_id FROM proxy_user u
             JOIN proxy_node n ON n.id = u.node_id
             WHERE n.server_id = ?1 AND u.name = ?2",
        )?;
        for name in names {
            let sub_id =
                stmt.query_row(params![server_id, name], |r| r.get::<_, Option<i64>>(1)).optional()?;
            out.push((name.clone(), sub_id.flatten()));
        }
        Ok(out)
    }

    /// 凭据级记账的定位：server 上这批凭据名 → proxy_user.id（方向 40）。
    pub fn proxy_user_ids_of_names(&self, server_id: i64, names: &[String]) -> Result<Vec<(String, i64)>> {
        let conn = self.conn();
        let mut out = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT u.name, u.id FROM proxy_user u
             JOIN proxy_node n ON n.id = u.node_id
             WHERE n.server_id = ?1 AND u.name = ?2",
        )?;
        for name in names {
            if let Ok(Some(pu_id)) =
                stmt.query_row(params![server_id, name], |r| r.get::<_, i64>(0)).optional()
            {
                out.push((name.clone(), pu_id));
            }
        }
        Ok(out)
    }

    /// 同一台服务器上是否已有同名凭据用户。v2ray 的用户计数器按名字聚合，
    /// 重名会把两个节点的用量记到一起，创建入口据此拒绝。
    pub fn proxy_user_name_taken(&self, server_id: i64, name: &str, exclude_node: i64) -> Result<bool> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM proxy_user u JOIN proxy_node n ON n.id = u.node_id
             WHERE n.server_id = ?1 AND u.name = ?2 AND u.node_id != ?3",
            params![server_id, name, exclude_node],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub fn reset_sub_token(&self, id: i64, token: &str) -> Result<()> {
        let res = self.conn().execute("UPDATE sub_user SET token = ?2 WHERE id = ?1", params![id, token])?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("订阅客户不存在，可能已被删除".into())));
        }
        Ok(())
    }

    pub fn delete_sub_user(&self, id: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("UPDATE proxy_user SET sub_user_id = NULL WHERE sub_user_id = ?1", [id])?;
        tx.execute("DELETE FROM sub_user WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    // ---- 节点流量采样（M4）----

    pub fn add_traffic_samples(&self, rows: &[(i64, &str, i64, i64, i64)]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for (server_id, tag, ts, rx, tx_bytes) in rows {
            tx.execute(
                "INSERT INTO traffic_samples (instance_id, node_tag, ts, rx, tx, server_id) VALUES (0,?1,?2,?3,?4,?5)",
                params![tag, ts, rx, tx_bytes, server_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 全网流量按桶聚合（概览走势图）：桶内 SUM 即该桶字节，缺桶（无流量时段）
    /// 由前端补零。桶对齐 unix 时间的 bucket_secs 整数倍（24h/小时桶、7d/6h 桶、
    /// 30d/天桶）。
    pub fn traffic_series(&self, since: i64, bucket_secs: i64) -> Result<Vec<(i64, i64, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT (ts/?2)*?2, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0)
             FROM traffic_samples WHERE ts >= ?1 GROUP BY ts/?2 ORDER BY ts/?2",
        )?;
        let rows = stmt.query_map(params![since, bucket_secs], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 历史采样压缩（housekeeping 每小时）：把 keep_days 天前的原始采样
    /// （约 5s 一行）改写成整点对齐的小时行（每 server_id+node_tag+小时一行
    /// SUM）。三个读取方（traffic_series / traffic_node_rank /
    /// proxy_traffic）全为 SUM 聚合，总量不变；today 边界是本地零点（整点
    /// 对齐）同样精确；24h/7d 窗口因 cutoff>7d 完全不受影响，仅 30d 档最老
    /// 一桶可有 ≤1h 误差。只改写 ts 非整点对齐的行——小时行自身整点对齐，
    /// 不会被二次改写，任务幂等；恰好落在整点的原始行保持原样（照样计入
    /// 一切查询）。
    pub fn compact_traffic_samples(&self, keep_days: i64) -> Result<usize> {
        let cutoff = Utc::now().timestamp() - keep_days * 86_400;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO traffic_samples (instance_id, node_tag, ts, rx, tx, server_id)
             SELECT 0, node_tag, (ts/3600)*3600, SUM(rx), SUM(tx), server_id
             FROM traffic_samples WHERE ts < ?1 AND ts % 3600 <> 0
             GROUP BY server_id, node_tag, ts/3600",
            [cutoff],
        )?;
        let removed = tx.execute("DELETE FROM traffic_samples WHERE ts < ?1 AND ts % 3600 <> 0", [cutoff])?;
        tx.commit()?;
        Ok(removed)
    }

    /// 按节点的流量排行（概览，窗口随调用方传的 since——与走势同范围）：
    /// 返回 (server_id, tag, rx, tx)，节点名由调用方映射。按总量降序。
    pub fn traffic_node_rank(&self, since: i64) -> Result<Vec<(i64, String, i64, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT server_id, node_tag, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0)
             FROM traffic_samples WHERE ts >= ?1
             GROUP BY server_id, node_tag ORDER BY SUM(rx)+SUM(tx) DESC",
        )?;
        let rows = stmt.query_map([since], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- 延迟探测告警（三期）----

    /// 路由到某节点的探测任务（节点 id，任务 id，间隔秒）。
    pub fn ping_pairs(&self) -> Result<Vec<(i64, i64, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT pn.node_id, pn.task_id, pt.interval
             FROM ping_node pn JOIN ping_task pt ON pt.id = pn.task_id",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 全部探测样本：`(节点, 任务, ts, latency)`，-1 为丢包行。
    pub fn ping_samples_since(&self, since: i64) -> Result<Vec<(i64, i64, i64, i64)>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT node_id, task_id, ts, latency FROM ping_record WHERE ts >= ?1 ORDER BY ts")?;
        let rows = stmt.query_map([since], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn ping_tasks_all(&self) -> Result<Vec<PingTask>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, name, target, interval, auto_join FROM ping_task")?;
        let rows = stmt.query_map([], |r| {
            Ok(PingTask {
                id: r.get(0)?,
                name: r.get(1)?,
                target: r.get(2)?,
                interval: r.get(3)?,
                auto_join: r.get::<_, i64>(4)? != 0,
                nodes: Vec::new(),
                base: None,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn ping_alert(&self, key: &str) -> Result<Option<PingAlertRow>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT key, node_id, task_id, kind, raised_at, confirmed, normal_streak, detail, recovered_at
                 FROM ping_alert WHERE key = ?1",
                [key],
                |r| {
                    Ok(PingAlertRow {
                        key: r.get(0)?,
                        node_id: r.get(1)?,
                        task_id: r.get(2)?,
                        kind: r.get(3)?,
                        raised_at: r.get(4)?,
                        confirmed: r.get(5)?,
                        normal_streak: r.get(6)?,
                        detail: r.get(7)?,
                        recovered_at: r.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    /// Hold 分支的计数落库：行可能还不存在（第一次确认时），必须是 upsert
    /// 而不是 UPDATE——否则确认计数永远停在 1，告警永远差一次。
    #[allow(clippy::too_many_arguments)]
    pub fn ping_alert_touch(
        &self,
        key: &str,
        node_id: i64,
        task_id: i64,
        kind: &str,
        confirmed: i64,
        normal_streak: i64,
        now: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO ping_alert (key, node_id, task_id, kind, raised_at, confirmed, normal_streak, checked_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7)
             ON CONFLICT(key) DO UPDATE SET
               confirmed = excluded.confirmed, normal_streak = excluded.normal_streak, checked_at = excluded.checked_at",
            params![key, node_id, task_id, kind, confirmed, normal_streak, now],
        )?;
        Ok(())
    }

    pub fn ping_alert_raise(
        &self,
        key: &str,
        node_id: i64,
        task_id: i64,
        kind: &str,
        detail: &str,
        now: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO ping_alert (key, node_id, task_id, kind, raised_at, confirmed, normal_streak, detail, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?5)
             ON CONFLICT(key) DO UPDATE SET
               raised_at = excluded.raised_at, confirmed = 0, normal_streak = 0,
               detail = excluded.detail, checked_at = excluded.checked_at, recovered_at = NULL",
            params![key, node_id, task_id, kind, now, detail],
        )?;
        Ok(())
    }

    pub fn ping_alert_recover(&self, key: &str, now: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE ping_alert SET recovered_at = ?2, confirmed = 0, normal_streak = 0, checked_at = ?2 WHERE key = ?1",
            params![key, now],
        )?;
        Ok(())
    }

    /// 进行中的告警：`(kind, 节点名, 任务名, 起报时刻, detail)`，起报时间排序。
    #[allow(clippy::type_complexity)] // 五元组返回是告警列表的既定形态
    pub fn ping_alert_active(&self) -> Result<Vec<(String, String, String, i64, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT pa.kind, COALESCE(n.name, '节点 ' || pa.node_id), COALESCE(pt.name, '任务 ' || pa.task_id),
                    pa.raised_at, pa.detail
             FROM ping_alert pa
             LEFT JOIN node n ON n.id = pa.node_id
             LEFT JOIN ping_task pt ON pt.id = pa.task_id
             WHERE pa.recovered_at IS NULL AND pa.raised_at > 0
             ORDER BY pa.raised_at",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 进行中告警的定位信息（孤儿清扫用）：任务或节点被删后，它的告警不再
    /// 有样本可评估，需要显式恢复。
    pub fn ping_alert_active_keys(&self) -> Result<Vec<(String, i64, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT key, node_id, task_id FROM ping_alert WHERE recovered_at IS NULL AND raised_at > 0",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn ping_alert_recovered_since(&self, since: i64) -> Result<i64> {
        let conn = self.conn();
        let n: i64 =
            conn.query_row("SELECT COUNT(*) FROM ping_alert WHERE recovered_at >= ?1", [since], |r| {
                r.get(0)
            })?;
        Ok(n)
    }

    // ---- MCP 代理（五期）----

    pub fn mcp_clients(&self) -> Result<Vec<McpClient>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT client_id, client_secret, name, created_at FROM mcp_clients ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(McpClient {
                client_id: r.get(0)?,
                client_secret: r.get(1)?,
                name: r.get(2)?,
                created_at: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn mcp_client(&self, client_id: &str) -> Result<Option<McpClient>> {
        Ok(self.mcp_clients()?.into_iter().find(|c| c.client_id == client_id))
    }

    pub fn upsert_mcp_client(&self, client_id: &str, secret: &str, name: &str, now: i64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO mcp_clients (client_id, client_secret, name, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(client_id) DO UPDATE SET client_secret = excluded.client_secret, name = excluded.name",
            params![client_id, secret, name, now],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_mcp_code(
        &self,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
        challenge: &str,
        method: &str,
        lease_hours: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO mcp_codes (code_hash, client_id, redirect_uri, challenge, method, lease_hours, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![code_hash, client_id, redirect_uri, challenge, method, lease_hours, expires_at],
        )?;
        Ok(())
    }

    /// 取授权码并即刻作废（授权码一次性）。返回 None = 不存在或已过期。
    #[allow(clippy::type_complexity)] // 五元组：client_id/redirect/challenge/method/时长
    pub fn take_mcp_code(
        &self,
        code_hash: &str,
        now: i64,
    ) -> Result<Option<(String, String, String, String, i64)>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT client_id, redirect_uri, challenge, method, lease_hours, expires_at FROM mcp_codes WHERE code_hash = ?1",
                [code_hash],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((client_id, redirect_uri, challenge, method, lease_hours, expires_at)) = row else {
            return Ok(None);
        };
        conn.execute("DELETE FROM mcp_codes WHERE code_hash = ?1", [code_hash])?;
        if expires_at < now {
            return Ok(None);
        }
        Ok(Some((client_id, redirect_uri, challenge, method, lease_hours)))
    }

    pub fn save_mcp_lease(
        &self,
        token_hash: &str,
        client_id: &str,
        scopes: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO mcp_tokens (token_hash, client_id, scopes, created_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![token_hash, client_id, scopes, created_at, expires_at],
        )?;
        Ok(())
    }

    /// 有效租约：未吊销、未过期。
    pub fn mcp_lease_valid(&self, token_hash: &str, now: i64) -> bool {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM mcp_tokens WHERE token_hash = ?1 AND revoked = 0 AND expires_at > ?2",
                params![token_hash, now],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    pub fn mcp_leases(&self) -> Result<Vec<McpLease>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT token_hash, client_id, scopes, created_at, expires_at, revoked FROM mcp_tokens ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(McpLease {
                token_hash: r.get(0)?,
                client_id: r.get(1)?,
                scopes: r.get(2)?,
                created_at: r.get(3)?,
                expires_at: r.get(4)?,
                revoked: r.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn revoke_mcp_lease(&self, token_hash: &str) -> Result<()> {
        self.conn().execute("UPDATE mcp_tokens SET revoked = 1 WHERE token_hash = ?1", [token_hash])?;
        Ok(())
    }

    pub fn log_mcp_operation(
        &self,
        lease: &str,
        tool: &str,
        node: &str,
        params: &str,
        at: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO mcp_operations (lease, tool, node, params, at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![lease, tool, node, params, at],
        )?;
        // 审计表封顶：只留最近 500 条。
        self.conn().execute(
            "DELETE FROM mcp_operations WHERE id NOT IN (SELECT id FROM mcp_operations ORDER BY id DESC LIMIT 500)",
            [],
        )?;
        Ok(())
    }

    #[allow(clippy::type_complexity)] // 五元组返回是操作审计列表的既定形态
    /// 操作审计最近 limit 条（安全页「最近操作」）。列序 tool/node/params/
    /// at/lease 对应 (String, String, String, i64, String)——元组第 4/5 位
    /// 曾与列序写反（at INTEGER 按 String 读），collect 整批 Err 被上层
    /// unwrap_or_default 吞掉，审计面板自上线起恒空（2026-10-27 修）。
    pub fn mcp_operations(&self, limit: i64) -> Result<Vec<(String, String, String, i64, String)>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT tool, node, params, at, lease FROM mcp_operations ORDER BY id DESC LIMIT ?1")?;
        let rows =
            stmt.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 顺带清理：过期授权码与过期租约（审计保留）。
    pub fn prune_mcp(&self, now: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM mcp_codes WHERE expires_at < ?1", [now])?;
        conn.execute("DELETE FROM mcp_tokens WHERE expires_at < ?1 AND revoked = 0", [now])?;
        Ok(())
    }

    // ---- 回程线路探测（四期）----

    pub fn route_tasks(&self) -> Result<Vec<RouteTask>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, name, target, interval, enabled, sort FROM route_task ORDER BY sort, id")?;
        let mut tasks = rows_to_route_tasks(stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)? != 0, r.get(5)?))
        })?)?;
        let mut links: HashMap<i64, Vec<i64>> = HashMap::new();
        let mut lstmt = conn.prepare("SELECT task_id, node_id FROM route_task_node")?;
        let lrows = lstmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
        for link in lrows {
            let (task_id, node_id) = link?;
            links.entry(task_id).or_default().push(node_id);
        }
        for t in &mut tasks {
            if let Some(nodes) = links.get(&t.id) {
                t.nodes = nodes.clone();
            }
        }
        Ok(tasks)
    }

    pub fn route_task(&self, id: i64) -> Result<Option<RouteTask>> {
        Ok(self.route_tasks()?.into_iter().find(|t| t.id == id))
    }

    /// 新建或更新（id=0 建）。指派节点整表替换。
    pub fn save_route_task(&self, t: &RouteTask) -> Result<i64> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let id = if t.id == 0 {
            tx.execute(
                "INSERT INTO route_task (name, target, interval, enabled, sort) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![t.name, t.target, t.interval, t.enabled as i64, t.sort],
            )?;
            tx.last_insert_rowid()
        } else {
            tx.execute(
                "UPDATE route_task SET name = ?2, target = ?3, interval = ?4, enabled = ?5, sort = ?6 WHERE id = ?1",
                params![t.id, t.name, t.target, t.interval, t.enabled as i64, t.sort],
            )?;
            t.id
        };
        tx.execute("DELETE FROM route_task_node WHERE task_id = ?1", [id])?;
        for node in &t.nodes {
            tx.execute(
                "INSERT OR IGNORE INTO route_task_node (task_id, node_id) VALUES (?1, ?2)",
                params![id, node],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn delete_route_task(&self, id: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM route_task WHERE id = ?1", [id])?;
        conn.execute("DELETE FROM route_status WHERE task_id = ?1", [id])?;
        conn.execute("DELETE FROM route_event WHERE task_id = ?1", [id])?;
        Ok(())
    }

    pub fn route_status(&self, task_id: i64, node_id: i64) -> Result<Option<RouteStatus>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT task_id, node_id, hops, line, baseline, probes, streak, recent, probed_at
                 FROM route_status WHERE task_id = ?1 AND node_id = ?2",
                params![task_id, node_id],
                |r| {
                    Ok(RouteStatus {
                        task_id: r.get(0)?,
                        node_id: r.get(1)?,
                        hops: r.get(2)?,
                        line: r.get(3)?,
                        baseline: r.get(4)?,
                        probes: r.get(5)?,
                        streak: r.get(6)?,
                        recent: r.get(7)?,
                        probed_at: r.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    /// 探测结果落库（upsert），返回写之前的旧状态。
    pub fn save_route_status(&self, s: &RouteStatus) -> Result<Option<RouteStatus>> {
        let old = self.route_status(s.task_id, s.node_id)?;
        self.conn().execute(
            "INSERT INTO route_status (task_id, node_id, hops, line, baseline, probes, streak, recent, probed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(task_id, node_id) DO UPDATE SET
               hops = excluded.hops, line = excluded.line, baseline = excluded.baseline,
               probes = excluded.probes, streak = excluded.streak, recent = excluded.recent,
               probed_at = excluded.probed_at",
            params![s.task_id, s.node_id, s.hops, s.line, s.baseline, s.probes, s.streak, s.recent, s.probed_at],
        )?;
        Ok(old)
    }

    pub fn add_route_event(
        &self,
        task_id: i64,
        node_id: i64,
        from_line: &str,
        to_line: &str,
        at: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO route_event (task_id, node_id, from_line, to_line, at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![task_id, node_id, from_line, to_line, at],
        )?;
        Ok(())
    }

    /// 最近的事件（回程卡与概览的「回程变化」计数），新→旧。
    #[allow(clippy::type_complexity)] // 五元组返回是事件列表的既定形态
    pub fn route_events(&self, limit: i64, since: i64) -> Result<Vec<(i64, i64, String, String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT task_id, node_id, from_line, to_line, at FROM route_event WHERE at >= ?2 ORDER BY at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit, since], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 按本地自然日 × 节点聚合的上下行（每日计费流量用：计费口径按节点所
    /// 在服务器的 traffic_mode 折算，必须先分节点再折算，日合计无法事后
    /// 拆回）。日界是本地零点；8 天前的采样已压缩成小时行，对整点时区
    /// （如东八区）日界仍精确，非整点时区最老一天可有 ≤1h 误差（与 30d
    /// 档既有口径一致）。无流量之日无行，由调用方补零。
    #[allow(clippy::type_complexity)] // 四元组返回是日账单行的既定形态
    pub fn traffic_daily_node(&self, since: i64) -> Result<Vec<(String, i64, String, i64, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT date(ts, 'unixepoch', 'localtime') AS d, server_id, node_tag,
                    COALESCE(SUM(rx),0), COALESCE(SUM(tx),0)
             FROM traffic_samples WHERE ts >= ?1
             GROUP BY d, server_id, node_tag ORDER BY d",
        )?;
        let rows =
            stmt.query_map([since], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn upsert_connection_logs(&self, server_id: i64, rows: &[ConnectionLogRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for r in rows {
            tx.execute(
                "INSERT INTO connection_log (conn_id, server_id, ts_first, ts_last, user, sub_user_id,
                                            inbound, network, source, host, port, up, down)
                 VALUES (?1, ?2, ?3, ?4, ?5,
                         (SELECT u.sub_user_id FROM proxy_user u JOIN proxy_node n ON n.id = u.node_id
                          WHERE n.server_id = ?2 AND u.name = ?5),
                         ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(server_id, conn_id) DO UPDATE SET
                   ts_last = excluded.ts_last, up = excluded.up, down = excluded.down,
                   sub_user_id = excluded.sub_user_id",
                params![
                    r.conn_id, server_id, r.first, r.last, r.user, r.inbound, r.network, r.source, r.host,
                    r.port, r.up, r.down
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 连接日志分页查询（ts_last 降序）。返回 (行, 总条数)。
    pub fn connection_logs(&self, f: &ConnLogFilter) -> Result<(Vec<serde_json::Value>, i64)> {
        let (where_sql, params) = conn_log_where(f);
        let conn = self.conn();
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM connection_log {where_sql}"),
            rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
            |r| r.get(0),
        )?;
        let page = (f.page.max(1) as i64 - 1).max(0);
        let mut sql = format!(
            "SELECT conn_id, ts_first, ts_last, user, COALESCE(sub_user_id, -1), inbound, source,
                    host, port, network, up, down, server_id
             FROM connection_log {where_sql} ORDER BY ts_last DESC LIMIT {CONN_LOG_PAGE} OFFSET {}",
            page * CONN_LOG_PAGE
        );
        let _ = &mut sql;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())), |r| {
            Ok(serde_json::json!({
                "conn_id": r.get::<_, String>(0)?,
                "first": r.get::<_, i64>(1)?,
                "last": r.get::<_, i64>(2)?,
                "user": r.get::<_, String>(3)?,
                "sub_user_id": r.get::<_, i64>(4)?,
                "inbound": r.get::<_, String>(5)?,
                "source": r.get::<_, String>(6)?,
                "host": r.get::<_, String>(7)?,
                "port": r.get::<_, i64>(8)?,
                "network": r.get::<_, String>(9)?,
                "up": r.get::<_, i64>(10)?,
                "down": r.get::<_, i64>(11)?,
                "server_id": r.get::<_, i64>(12)?,
            }))
        })?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        Ok((rows, total))
    }

    /// 汇总：请求量最多的地址（按连接数）与消耗最多的客户端（按字节）。
    pub fn connection_log_summary(
        &self,
        f: &ConnLogFilter,
    ) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>)> {
        let (where_sql, params) = conn_log_where(f);
        let conn = self.conn();
        // 条件里的参数在 where 中可能多次引用同一下标——params_from_iter 按顺序取，
        // 这里 where 构造保证同下标同值，重复引用不增加参数个数，因此按 uses 计数。
        // 简化：直接把 where 的参数克隆两份。
        let hosts = {
            let sql = format!(
                "SELECT host, COUNT(*) AS c, SUM(up)+SUM(down) AS bytes FROM connection_log {where_sql}
                 GROUP BY host ORDER BY c DESC LIMIT 10"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())), |r| {
                Ok(serde_json::json!({ "host": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?, "bytes": r.get::<_, i64>(2)? }))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let clients = {
            // 按客户端 IP 归组（剥掉源端口）：同一客户端的多次连接次数累计，
            // 否则每次连接的源端口不同会被拆成多行。v6 来源带方括号，先截到 ']'。
            let sql = format!(
                "SELECT CASE WHEN instr(source, ']') > 0 THEN substr(source, 1, instr(source, ']'))
                             ELSE substr(source, 1, instr(source, ':') - 1) END AS ip,
                        COUNT(*) AS c, SUM(up)+SUM(down) AS bytes
                 FROM connection_log {where_sql}
                 GROUP BY ip ORDER BY c DESC LIMIT 10"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())), |r| {
                Ok(serde_json::json!({ "source": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?, "bytes": r.get::<_, i64>(2)? }))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        Ok((hosts, clients))
    }

    /// CSV 导出行（同筛选，最多 limit 行）：(ts, user, source, inbound,
    /// host, port, network, up, down)。
    #[allow(clippy::type_complexity)] // 九元组即 CSV 列序，拆别名反而隔一层
    pub fn connection_logs_export(
        &self,
        f: &ConnLogFilter,
        limit: i64,
    ) -> Result<Vec<(i64, String, String, String, String, i64, String, i64, i64)>> {
        let (where_sql, params) = conn_log_where(f);
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT ts_last, user, source, inbound, host, port, network, up, down
             FROM connection_log {where_sql} ORDER BY ts_last DESC LIMIT {limit}"
        ))?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 连接日志按保留期清理（M14）。
    pub fn prune_connection_logs(&self, keep_days: i64) -> Result<usize> {
        let cutoff = Utc::now().timestamp() - keep_days * 86_400;
        Ok(self.conn().execute("DELETE FROM connection_log WHERE ts_last < ?1", [cutoff])?)
    }

    /// 每个节点的流量合计：今日（本地时区自然日）与累计。
    #[allow(clippy::type_complexity)] // 六元组即排行榜行，拆别名反而隔一层
    pub fn proxy_traffic(&self) -> Result<Vec<(i64, String, i64, i64, i64, i64)>> {
        // (server_id, tag, today_rx, today_tx, total_rx, total_tx)
        let conn = self.conn();
        let day_start = Local::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let mut stmt = conn.prepare(
            "SELECT server_id, node_tag,
                    COALESCE(SUM(CASE WHEN ts >= ?1 THEN rx END), 0),
                    COALESCE(SUM(CASE WHEN ts >= ?1 THEN tx END), 0),
                    COALESCE(SUM(rx), 0), COALESCE(SUM(tx), 0)
             FROM traffic_samples GROUP BY server_id, node_tag",
        )?;
        let rows = stmt.query_map([day_start], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- Realm 中转规则（M5）----

    pub fn relay_rules(&self) -> Result<Vec<RelayRule>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM relay_rules ORDER BY id")?;
        let rows = stmt.query_map([], row_to_relay_rule)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn relay_rule(&self, id: i64) -> Result<Option<RelayRule>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM relay_rules WHERE id = ?1", [id], row_to_relay_rule)
            .optional()?)
    }

    pub fn create_relay_rule(&self, r: &RelayRule) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO relay_rules (server_id, name, listen_port, target, enabled, created_at, origin_link,
               protocol, note, balance, transport, tls_sni, tls_insecure, ws_path,
               exit_server_id, exit_listen_port, listen_host, through, interface, send_proxy, mptcp, entry_backups)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
            params![
                r.server_id, r.name, r.listen_port, r.target, r.enabled as i64, Utc::now().timestamp(), r.origin_link,
                r.protocol, r.note, r.balance, r.transport, r.tls_sni, r.tls_insecure as i64, r.ws_path,
                r.exit_server_id, r.exit_listen_port, r.listen_host, r.through, r.interface, r.send_proxy as i64, r.mptcp as i64,
                r.entry_backups,
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn update_relay_rule(&self, r: &RelayRule) -> Result<()> {
        let res = self.conn().execute(
            "UPDATE relay_rules SET server_id=?2, name=?3, listen_port=?4, target=?5, enabled=?6, origin_link=?7,
               protocol=?8, note=?9, balance=?10, transport=?11, tls_sni=?12, tls_insecure=?13, ws_path=?14,
               exit_server_id=?15, exit_listen_port=?16, listen_host=?17, through=?18, interface=?19,
               send_proxy=?20, mptcp=?21, entry_backups=?22
             WHERE id=?1",
            params![
                r.id, r.server_id, r.name, r.listen_port, r.target, r.enabled as i64, r.origin_link,
                r.protocol, r.note, r.balance, r.transport, r.tls_sni, r.tls_insecure as i64, r.ws_path,
                r.exit_server_id, r.exit_listen_port, r.listen_host, r.through, r.interface,
                r.send_proxy as i64, r.mptcp as i64, r.entry_backups,
            ],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("中转规则不存在，可能已被删除".into())));
        }
        Ok(())
    }

    pub fn delete_relay_rule(&self, id: i64) -> Result<()> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM relay_targets WHERE rule_id = ?1", [id])?;
        tx.execute("DELETE FROM relay_hop_state WHERE rule_id = ?1", [id])?;
        tx.execute("DELETE FROM relay_rules WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    // ---- 落地目标（M24）：多落地 + 负载均衡 + 健康状态 ----

    /// DDNS 同步路径写回最近一次同步进 DNS 的 IP（不进 NodePatch，前端只读）。
    pub fn update_dns_ip(&self, id: i64, ip: &str) -> Result<()> {
        self.conn().execute("UPDATE node SET dns_ip = ?2 WHERE id = ?1", rusqlite::params![id, ip])?;
        Ok(())
    }

    /// 自动故障摘除（relay_health::failover_watch）更新目标健康态（up/down）。
    pub fn update_relay_target_state(&self, id: i64, state: &str) -> Result<()> {
        self.conn()
            .execute("UPDATE relay_targets SET state = ?2 WHERE id = ?1", rusqlite::params![id, state])?;
        Ok(())
    }

    /// 全部落地目标（渲染用，按 rule_id + seq 排序）。
    pub fn relay_targets(&self) -> Result<Vec<RelayTarget>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM relay_targets ORDER BY rule_id, seq, id")?;
        let rows = stmt.query_map([], row_to_relay_target)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn relay_targets_of(&self, rule_id: i64) -> Result<Vec<RelayTarget>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM relay_targets WHERE rule_id = ?1 ORDER BY seq, id")?;
        let rows = stmt.query_map([rule_id], row_to_relay_target)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 整体替换一条规则的目标列表。同 (host, port) 的行保留健康状态——
    /// 编辑排序/改权重不该让探测计数清零；其余行连同状态一起丢弃。
    pub fn replace_relay_targets(&self, rule_id: i64, targets: &[RelayTarget]) -> Result<()> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let mut keep: HashMap<(String, i64), RelayTarget> = HashMap::new();
        {
            let mut stmt = tx.prepare("SELECT * FROM relay_targets WHERE rule_id = ?1")?;
            let rows = stmt.query_map([rule_id], row_to_relay_target)?;
            for t in rows {
                let t = t?;
                keep.insert((t.host.clone(), t.port), t);
            }
        }
        tx.execute("DELETE FROM relay_targets WHERE rule_id = ?1", [rule_id])?;
        for (i, t) in targets.iter().enumerate() {
            let old = keep.get(&(t.host.clone(), t.port));
            tx.execute(
                "INSERT INTO relay_targets (rule_id, seq, host, port, weight, enabled, state,
                   fail_streak, ok_streak, down_since, last_checked, last_latency_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    rule_id,
                    i as i64,
                    t.host,
                    t.port,
                    if t.weight > 0 { t.weight } else { 1 },
                    t.enabled as i64,
                    old.map(|o| o.state.clone()).unwrap_or_else(|| "unknown".into()),
                    old.map(|o| o.fail_streak).unwrap_or(0),
                    old.map(|o| o.ok_streak).unwrap_or(0),
                    old.map(|o| o.down_since).unwrap_or(0),
                    old.map(|o| o.last_checked).unwrap_or(0),
                    old.and_then(|o| o.last_latency_ms),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // 健康检查已移除：状态/样本/历史相关函数随功能删除，relay_targets 的
    // state 等列与迁移 38 建的表保留（schema 与已部署库一致，不折腾迁移）。

    // ---- 订阅转换 v2（miaomiaowu 架构）：节点池 / 外部订阅源 / 模板 / 片段 / 订阅文件 ----

    pub fn sub_nodes(&self) -> Result<Vec<SubNode>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM sub_nodes ORDER BY id")?;
        let rows = stmt.query_map([], row_to_sub_node)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn sub_node(&self, id: i64) -> Result<Option<SubNode>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM sub_nodes WHERE id = ?1", [id], row_to_sub_node)
            .optional()?)
    }

    /// 导入/同步一个节点：同 (protocol, server, port) upsert 刷新名称/形态/标签
    /// （同步式快照），返回 (id, 是否新建)。
    pub fn upsert_sub_node(&self, n: &SubNode) -> Result<(i64, bool)> {
        let existing: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM sub_nodes WHERE protocol = ?1 AND server = ?2 AND port = ?3",
                params![n.protocol, n.server, n.port],
                |r| r.get(0),
            )
            .optional()?;
        let tags = serde_json::to_string(&n.tags).unwrap_or_else(|_| "[]".into());
        if let Some(id) = existing {
            self.conn().execute(
                "UPDATE sub_nodes SET name=?2, raw_link=?3, clash_config=?4, tags=?5, proxy_node_id=?6 WHERE id=?1",
                params![id, n.name, n.raw_link, n.clash_config, tags, n.proxy_node_id],
            )?;
            return Ok((id, false));
        }
        self.conn().execute(
            "INSERT INTO sub_nodes (name, raw_link, clash_config, protocol, server, port, tags, source_url, enabled, created_at, proxy_node_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![n.name, n.raw_link, n.clash_config, n.protocol, n.server, n.port, tags, n.source_url, n.enabled as i64, Utc::now().timestamp(), n.proxy_node_id],
        )?;
        Ok((self.conn().last_insert_rowid(), true))
    }

    pub fn update_sub_node(&self, n: &SubNode) -> Result<()> {
        let tags = serde_json::to_string(&n.tags).unwrap_or_else(|_| "[]".into());
        let res = self.conn().execute(
            "UPDATE sub_nodes SET name=?2, tags=?3, note=?4, enabled=?5 WHERE id=?1",
            params![n.id, n.name, tags, n.note, n.enabled as i64],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("节点不存在，可能已被删除".into())));
        }
        Ok(())
    }

    pub fn delete_sub_node(&self, id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM sub_nodes WHERE id = ?1", [id])?;
        Ok(())
    }

    /// 删除一个外部订阅源的全部关联节点（同步前清场）。
    pub fn delete_sub_nodes_by_source(&self, url: &str) -> Result<usize> {
        self.conn().execute("DELETE FROM sub_nodes WHERE source_url = ?1", [url]).map_err(Into::into)
    }

    /// 按 (protocol, server, port) 去重，保留最早一条，返回删除数。
    pub fn dedup_sub_nodes(&self) -> Result<usize> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let removed = tx.execute(
            "DELETE FROM sub_nodes
             WHERE id NOT IN (SELECT MIN(id) FROM sub_nodes GROUP BY protocol, server, port)",
            [],
        )?;
        tx.commit()?;
        Ok(removed)
    }

    /// 批量重命名（prefix 前缀 / replace 查找替换），返回更新数。
    pub fn rename_sub_nodes(&self, mode: &str, a: &str, b: &str) -> Result<usize> {
        // 先取节点再开事务：conn() 是非重入锁，持锁期间不得再走查询方法。
        let nodes = self.sub_nodes()?;
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let mut updated = 0;
        for n in nodes {
            let name = if mode == "prefix" {
                if n.name.starts_with(a) {
                    continue;
                }
                format!("{a}{}", n.name)
            } else {
                if a.is_empty() || !n.name.contains(a) {
                    continue;
                }
                n.name.replace(a, b)
            };
            if name != n.name && !name.trim().is_empty() {
                tx.execute("UPDATE sub_nodes SET name = ?2 WHERE id = ?1", params![n.id, name])?;
                updated += 1;
            }
        }
        tx.commit()?;
        Ok(updated)
    }

    pub fn set_sub_node_latency(&self, id: i64, latency_ms: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE sub_nodes SET latency_ms = ?2, probed_at = ?3 WHERE id = ?1",
            params![id, latency_ms, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub fn sub_sources(&self) -> Result<Vec<SubSource>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM sub_sources ORDER BY id")?;
        let rows = stmt.query_map([], row_to_sub_source)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn sub_source(&self, id: i64) -> Result<Option<SubSource>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM sub_sources WHERE id = ?1", [id], row_to_sub_source)
            .optional()?)
    }

    /// 按 URL upsert 外部订阅源（重复导入幂等），返回 (id, 是否新建)。
    pub fn upsert_sub_source(&self, s: &SubSource) -> Result<(i64, bool)> {
        let existing: Option<i64> = self
            .conn()
            .query_row("SELECT id FROM sub_sources WHERE url = ?1", [&s.url], |r| r.get(0))
            .optional()?;
        if let Some(id) = existing {
            self.conn().execute(
                "UPDATE sub_sources SET name=?2, user_agent=?3, auto_update=?4, interval_min=?5, info=?6 WHERE id=?1",
                params![id, s.name, s.user_agent, s.auto_update as i64, s.interval_min, s.info],
            )?;
            return Ok((id, false));
        }
        self.conn().execute(
            "INSERT INTO sub_sources (url, name, user_agent, auto_update, interval_min, info, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                s.url,
                s.name,
                s.user_agent,
                s.auto_update as i64,
                s.interval_min,
                s.info,
                Utc::now().timestamp()
            ],
        )?;
        Ok((self.conn().last_insert_rowid(), true))
    }

    pub fn update_sub_source(&self, s: &SubSource) -> Result<()> {
        let res = self.conn().execute(
            "UPDATE sub_sources SET name=?2, user_agent=?3, auto_update=?4, interval_min=?5 WHERE id=?1",
            params![s.id, s.name, s.user_agent, s.auto_update as i64, s.interval_min],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("订阅源不存在，可能已被删除".into())));
        }
        Ok(())
    }

    pub fn delete_sub_source(&self, id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM sub_sources WHERE id = ?1", [id])?;
        Ok(())
    }

    /// 同步完成回写：上游流量信息 + 节点数 + 时间。
    pub fn set_sub_source_sync(&self, id: i64, info: &str, node_count: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE sub_sources SET info=?2, node_count=?3, last_sync=?4 WHERE id=?1",
            params![id, info, node_count, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub fn sub_templates(&self) -> Result<Vec<SubTemplate>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM sub_templates ORDER BY is_builtin DESC, id")?;
        let rows = stmt.query_map([], row_to_sub_template)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn sub_template(&self, name: &str) -> Result<Option<SubTemplate>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM sub_templates WHERE name = ?1", [name], row_to_sub_template)
            .optional()?)
    }

    pub fn create_sub_template(&self, t: &SubTemplate) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO sub_templates (name, note, is_builtin, content, created_at) VALUES (?1,?2,?3,?4,?5)",
            params![t.name, t.note, t.is_builtin as i64, t.content, Utc::now().timestamp()],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// 更新模板的 name/note/content。改名时（name != old_name）同事务级联改写
    /// sub_profiles.template_name——订阅文件按名字引用模板，不级联会集体悬空。
    pub fn update_sub_template(&self, t: &SubTemplate, old_name: &str) -> Result<()> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let res = tx.execute(
            "UPDATE sub_templates SET name=?2, note=?3, content=?4 WHERE id=?1",
            params![t.id, t.name, t.note, t.content],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("模板不存在，可能已被删除".into())));
        }
        if t.name != old_name {
            tx.execute(
                "UPDATE sub_profiles SET template_name=?2 WHERE template_name=?1",
                params![old_name, t.name],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_sub_template(&self, id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM sub_templates WHERE id = ?1 AND is_builtin = 0", [id])?;
        Ok(())
    }

    // ---- 规则模式来源管理（自定义来源 + 内置覆盖）----

    pub fn rule_sources(&self, kind: &str) -> Result<Vec<RuleSource>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM conv_rule_sources WHERE kind = ?1 ORDER BY id")?;
        let rows = stmt.query_map([kind], row_to_rule_source)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn rule_source(&self, id: i64) -> Result<Option<RuleSource>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM conv_rule_sources WHERE id = ?1", [id], row_to_rule_source)
            .optional()?)
    }

    pub fn create_rule_source(&self, s: &RuleSource) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO conv_rule_sources (kind, name, url, data, last_sync, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![s.kind, s.name, s.url, s.data, s.last_sync, if s.created_at > 0 { s.created_at } else { Utc::now().timestamp() }],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn update_rule_source_name(&self, id: i64, name: &str) -> Result<()> {
        self.conn().execute("UPDATE conv_rule_sources SET name = ?2 WHERE id = ?1", params![id, name])?;
        Ok(())
    }

    /// 模板来源改名 + 改 URL（预设清单行内编辑）。类别来源不走此方法（其 url 与 data 耦合）。
    pub fn update_rule_source(&self, id: i64, name: &str, url: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE conv_rule_sources SET name = ?2, url = ?3 WHERE id = ?1",
            params![id, name, url],
        )?;
        Ok(())
    }

    /// 类别源刷新快照（同步）：替换 data 并打 last_sync 时间戳。
    pub fn set_rule_source_data(&self, id: i64, data: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE conv_rule_sources SET data = ?2, last_sync = ?3 WHERE id = ?1",
            params![id, data, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub fn delete_rule_source(&self, id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM conv_rule_sources WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn builtin_override(&self, target: &str) -> Result<Option<Value>> {
        let conn = self.conn();
        let raw: Option<String> = conn
            .query_row("SELECT value FROM conv_builtin_overrides WHERE target = ?1", [target], |r| r.get(0))
            .optional()?;
        Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
    }

    pub fn set_builtin_override(&self, target: &str, value: &Value) -> Result<()> {
        self.conn().execute(
            "INSERT INTO conv_builtin_overrides (target, value, updated_at) VALUES (?1,?2,?3)
             ON CONFLICT(target) DO UPDATE SET value = ?2, updated_at = ?3",
            params![target, value.to_string(), Utc::now().timestamp()],
        )?;
        Ok(())
    }

    /// 删除覆盖（恢复代码默认）。返回是否确有覆盖被删。
    pub fn delete_builtin_override(&self, target: &str) -> Result<bool> {
        let n = self.conn().execute("DELETE FROM conv_builtin_overrides WHERE target = ?1", [target])?;
        Ok(n > 0)
    }

    /// 所有内置覆盖（target → value），供 effective 解析批量取用。
    pub fn builtin_overrides(&self) -> Result<Vec<(String, Value)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT target, value FROM conv_builtin_overrides ORDER BY target")?;
        let rows = stmt.query_map([], |r| {
            let t: String = r.get(0)?;
            let v: String = r.get(1)?;
            Ok((t, serde_json::from_str::<Value>(&v).unwrap_or(Value::Null)))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn sub_snippets(&self) -> Result<Vec<SubSnippet>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM sub_rule_snippets ORDER BY id")?;
        let rows = stmt.query_map([], row_to_sub_snippet)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn sub_snippet(&self, id: i64) -> Result<Option<SubSnippet>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM sub_rule_snippets WHERE id = ?1", [id], row_to_sub_snippet)
            .optional()?)
    }

    pub fn create_sub_snippet(&self, s: &SubSnippet) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO sub_rule_snippets (name, kind, mode, content, enabled, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![s.name, s.kind, s.mode, s.content, s.enabled as i64, Utc::now().timestamp()],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn update_sub_snippet(&self, s: &SubSnippet) -> Result<()> {
        let res = self.conn().execute(
            "UPDATE sub_rule_snippets SET name=?2, kind=?3, mode=?4, content=?5, enabled=?6 WHERE id=?1",
            params![s.id, s.name, s.kind, s.mode, s.content, s.enabled as i64],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("规则片段不存在，可能已被删除".into())));
        }
        Ok(())
    }

    pub fn delete_sub_snippet(&self, id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM sub_rule_snippets WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn sub_profiles(&self) -> Result<Vec<SubProfile>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM sub_profiles ORDER BY id")?;
        let rows = stmt.query_map([], row_to_sub_profile)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn sub_profile(&self, id: i64) -> Result<Option<SubProfile>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM sub_profiles WHERE id = ?1", [id], row_to_sub_profile)
            .optional()?)
    }

    pub fn sub_profile_by_token(&self, token: &str) -> Result<Option<SubProfile>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM sub_profiles WHERE token = ?1", [token], row_to_sub_profile)
            .optional()?)
    }

    pub fn create_sub_profile(&self, p: &SubProfile) -> Result<i64> {
        let tags = serde_json::to_string(&p.selected_tags).unwrap_or_else(|_| "[]".into());
        let snippets = serde_json::to_string(&p.snippet_ids).unwrap_or_else(|_| "[]".into());
        let overrides = serde_json::to_string(&p.group_overrides).unwrap_or_else(|_| "{}".into());
        let categories = serde_json::to_string(&p.selected_categories).unwrap_or_else(|_| "[]".into());
        let sel_nodes = serde_json::to_string(&p.selected_nodes).unwrap_or_else(|_| "[]".into());
        self.conn().execute(
            "INSERT INTO sub_profiles (name, token, template_name, selected_tags, snippet_ids, expires_at, group_overrides, selected_categories, selected_nodes, static_content, agent_dist, enabled, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![p.name, p.token, p.template_name, tags, snippets, p.expires_at, overrides, categories, sel_nodes, p.static_content, p.agent_dist as i64, p.enabled as i64, Utc::now().timestamp()],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn update_sub_profile(&self, p: &SubProfile) -> Result<()> {
        let tags = serde_json::to_string(&p.selected_tags).unwrap_or_else(|_| "[]".into());
        let snippets = serde_json::to_string(&p.snippet_ids).unwrap_or_else(|_| "[]".into());
        let overrides = serde_json::to_string(&p.group_overrides).unwrap_or_else(|_| "{}".into());
        let categories = serde_json::to_string(&p.selected_categories).unwrap_or_else(|_| "[]".into());
        let sel_nodes = serde_json::to_string(&p.selected_nodes).unwrap_or_else(|_| "[]".into());
        let res = self.conn().execute(
            "UPDATE sub_profiles SET name=?2, template_name=?3, selected_tags=?4, snippet_ids=?5, expires_at=?6, group_overrides=?7, selected_categories=?8, selected_nodes=?9, static_content=?10, agent_dist=?11, enabled=?12 WHERE id=?1",
            params![p.id, p.name, p.template_name, tags, snippets, p.expires_at, overrides, categories, sel_nodes, p.static_content, p.agent_dist as i64, p.enabled as i64],
        )?;
        if res == 0 {
            return Err(anyhow::Error::msg(crate::Shown("订阅不存在，可能已被删除".into())));
        }
        Ok(())
    }

    pub fn reset_sub_profile_token(&self, id: i64, token: &str) -> Result<()> {
        self.conn().execute("UPDATE sub_profiles SET token = ?2 WHERE id = ?1", params![id, token])?;
        Ok(())
    }

    pub fn delete_sub_profile(&self, id: i64) -> Result<()> {
        // 引用该方案的客户解除绑定（订阅回落裸节点输出）。
        self.conn().execute("UPDATE sub_user SET profile_id = NULL WHERE profile_id = ?1", [id])?;
        self.conn().execute("DELETE FROM sub_profiles WHERE id = ?1", [id])?;
        Ok(())
    }

    /// 客户解除方案绑定（方案删除时由调用方触发）。
    pub fn clear_sub_user_profile(&self, profile_id: i64) -> Result<()> {
        self.conn().execute("UPDATE sub_user SET profile_id = NULL WHERE profile_id = ?1", [profile_id])?;
        Ok(())
    }

    pub fn add_latency_sample(&self, node_id: i64, avg_ms: f64, loss: f64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO latency_samples (node_id, ts, avg_ms, loss) VALUES (?1,?2,?3,?4)",
            params![node_id, Utc::now().timestamp(), avg_ms, loss],
        )?;
        Ok(())
    }

    // ---- agent job audit（M3）----

    pub fn add_agent_job(&self, server_id: i64, method: &str, detail: &str) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO agent_jobs (server_id, method, state, detail, created_at) VALUES (?1,?2,'pushed',?3,?4)",
            params![server_id, method, detail, Utc::now().timestamp()],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn finish_agent_job(&self, id: i64, state: &str, detail: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE agent_jobs SET state = ?2, detail = ?3 WHERE id = ?1",
            params![id, state, detail],
        )?;
        Ok(())
    }

    // ---- nodes ----

    pub fn nodes(&self) -> Result<Vec<Node>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM node ORDER BY sort, id")?;
        let rows = stmt.query_map([], |r| Ok(row_to_node(r)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn node(&self, id: i64) -> Result<Option<Node>> {
        Ok(self
            .conn()
            .query_row("SELECT * FROM node WHERE id = ?1", [id], |r| Ok(row_to_node(r)))
            .optional()?)
    }

    /// Creates a node and returns its id.
    ///
    /// One transaction: `accumulate` reads the `traffic` row on every report, so
    /// a node lacking one cannot report. The node also takes every `auto_join`
    /// probe here, at most [`Self::MAX_PROBES_PER_NODE`] rows, a limit
    /// `save_ping_task` enforces.
    pub fn create_node(&self, n: &Node, token: &str) -> Result<i64> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            // A new node belongs at the end. The caller sends sort 0, which would
            // tie with whatever the last reorder placed first.
            "INSERT INTO node (name, token, sort, public, price, currency, billing_cycle,
                               expires_at, remark, traffic_limit, traffic_mode, traffic_reset_day, created_at,
                               group_name)
             VALUES (?1,?2,(SELECT COALESCE(MAX(sort),-1)+1 FROM node),?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                n.name,
                token,
                n.public,
                n.price,
                n.currency,
                n.billing_cycle,
                n.expires_at,
                n.remark,
                n.traffic_limit,
                n.traffic_mode,
                n.traffic_reset_day,
                Utc::now().timestamp(),
                n.group
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute("INSERT INTO traffic (node_id) VALUES (?1)", [id])?;
        tx.execute(
            "INSERT INTO ping_node (task_id, node_id) SELECT id, ?1 FROM ping_task WHERE auto_join",
            [id],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// How many nodes were created at or after `ts`. Bounds what one registration
    /// window can add; see `api::REGISTER_LIMIT`.
    pub fn nodes_created_since(&self, ts: i64) -> Result<i64> {
        Ok(self.conn().query_row("SELECT COUNT(*) FROM node WHERE created_at >= ?1", [ts], |r| r.get(0))?)
    }

    /// Records when the node last reported, with the capacities that report
    /// carried. Written with each metric row and once more as the session ends,
    /// so an offline node shows the disk it last had rather than the one it
    /// connected with. A capacity absent from `metrics` keeps its stored value.
    pub fn touch_seen(&self, id: i64, ts: i64, metrics: &serde_json::Value) -> Result<()> {
        let n = |k: &str| metrics.get(k).and_then(serde_json::Value::as_i64);
        self.conn()
            .prepare_cached(
                "UPDATE node SET last_seen=?2, mem_total=COALESCE(?3,mem_total),
                                 swap_total=COALESCE(?4,swap_total), disk_total=COALESCE(?5,disk_total)
                 WHERE id=?1",
            )?
            .execute(params![id, ts, n("mem_total"), n("swap_total"), n("disk_total")])?;
        Ok(())
    }

    /// False when no node has this id.
    pub fn update_node(&self, id: i64, n: &NodePatch) -> Result<bool> {
        self.update_nodes(&[id], n)
    }

    /// Applies one patch to every node in `ids` in a single transaction. False,
    /// with nothing written, when any of them no longer exists: a batch applied
    /// to part of what was selected would leave the panel to work out which part.
    pub fn update_nodes(&self, ids: &[i64], n: &NodePatch) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut update = tx.prepare(
                "UPDATE node SET name=COALESCE(?2,name), sort=COALESCE(?3,sort), public=COALESCE(?4,public),
                                 price=COALESCE(?5,price), currency=COALESCE(?6,currency),
                                 billing_cycle=COALESCE(?7,billing_cycle),
                                 expires_at=CASE WHEN ?8 THEN ?9 ELSE expires_at END,
                                 traffic_limit=COALESCE(?10,traffic_limit),
                                 traffic_mode=COALESCE(?11,traffic_mode),
                                 traffic_reset_day=COALESCE(?12,traffic_reset_day),
                                 notify=COALESCE(?13,notify), country_pin=COALESCE(?14,country_pin),
                                 ipv4_pin=COALESCE(?15,ipv4_pin), ipv6_pin=COALESCE(?16,ipv6_pin),
                                 group_name=COALESCE(?17,group_name),
                                 dns_name=COALESCE(?18,dns_name),
                                 purchase_url=COALESCE(?19,purchase_url)
                 WHERE id=?1",
            )?;
            for id in ids {
                let found = update.execute(params![
                    id,
                    n.name,
                    n.sort,
                    n.public,
                    n.price,
                    n.currency,
                    n.billing_cycle,
                    n.expires_at.is_some(),
                    n.expires_at.as_ref().and_then(|v| v.as_deref()),
                    n.traffic_limit,
                    n.traffic_mode,
                    n.traffic_reset_day,
                    n.notify,
                    n.country_pin,
                    n.ipv4_pin,
                    n.ipv6_pin,
                    n.group,
                    n.dns_name,
                    n.purchase_url
                ])?;
                // Dropping the transaction uncommitted rolls back the nodes
                // already updated.
                if found == 0 {
                    return Ok(false);
                }
            }
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn set_expiry(&self, id: i64, date: &str) -> Result<()> {
        self.conn().execute("UPDATE node SET expires_at=?2 WHERE id=?1", params![id, date])?;
        Ok(())
    }

    pub fn set_down_since(&self, id: i64, ts: i64) -> Result<()> {
        self.conn().execute("UPDATE node SET down_since=?2 WHERE id=?1", params![id, ts])?;
        Ok(())
    }

    pub fn reorder_nodes(&self, ids: &[i64]) -> Result<()> {
        self.reorder("node", ids)
    }

    pub fn reorder_ping_tasks(&self, ids: &[i64]) -> Result<()> {
        self.reorder("ping_task", ids)
    }

    /// Renumbers `sort` from a list that must name every row exactly once, so a
    /// tab that missed an insert or a delete cannot renumber around it.
    fn reorder(&self, table: &str, ids: &[i64]) -> Result<()> {
        let unique: HashSet<_> = ids.iter().collect();
        if unique.len() != ids.len() {
            refuse!("排序里有重复的条目");
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
        if count as usize != ids.len() {
            refuse!("列表已在别处改动，刷新后再排序");
        }
        let sql = format!("UPDATE {table} SET sort=?2 WHERE id=?1");
        for (sort, id) in ids.iter().enumerate() {
            if tx.execute(&sql, params![id, sort as i64])? != 1 {
                refuse!("列表已在别处改动，刷新后再排序");
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// False when no node has this id.
    pub fn delete_node(&self, id: i64) -> Result<bool> {
        let conn = self.conn();
        // `ping_record` carries no foreign key -- it is WITHOUT ROWID and keyed
        // for the chart query -- so it is cleared explicitly. SQLite reassigns a
        // deleted node's id to the next node created, which would otherwise
        // inherit the removed machine's latency chart.
        conn.execute("DELETE FROM ping_record WHERE node_id = ?1", [id])?;
        Ok(conn.execute("DELETE FROM node WHERE id = ?1", [id])? > 0)
    }

    /// Replaces a node's token, which immediately locks out the old one. False
    /// when no node has this id.
    pub fn reset_token(&self, id: i64, token: &str) -> Result<bool> {
        Ok(self.conn().execute("UPDATE node SET token=?2 WHERE id=?1", params![id, token])? > 0)
    }

    pub fn node_by_token(&self, token: &str) -> Result<Option<i64>> {
        Ok(self.conn().query_row("SELECT id FROM node WHERE token = ?1", [token], |r| r.get(0)).optional()?)
    }

    /// Stores the slow-changing facts an agent sends on connect, and reports
    /// whether the node still requires a country lookup for `source`, the address
    /// `agent_ws::country_source` chose. An empty `source` has no country and is
    /// never owed one.
    ///
    /// A new source invalidates the previous country, so the two move together in
    /// one statement: `SET` reads the row as it was, so the comparison is against
    /// the stored address rather than the one being written. The pair replaced
    /// moves to `country_prev_ip` / `country_prev` if it had an answer, and a
    /// source equal to that address takes its answer back without a lookup.
    pub fn save_facts(&self, id: i64, f: &serde_json::Value, ip: &str, source: &str) -> Result<bool> {
        // The same rule `api::agent_register` applies to the name it receives:
        // these values come from an unvouched machine, control characters break
        // the panel's rows, and the length must be bounded. Six of them -- os,
        // kernel, arch, virt, cpu_name, agent_version -- go straight into the
        // anonymous public frame, which is rebuilt and pushed to every viewer
        // every two seconds, so without a ceiling one node would determine that
        // frame's size. 128 rather than 64: a real PRETTY_NAME runs to about 60
        // characters and a CPU model to about 50.
        let s = |k: &str| {
            f.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_control())
                .take(128)
                .collect::<String>()
        };
        let n = |k: &str| f.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        let conn = self.conn();
        conn.execute(
            "UPDATE node SET hostname=?2, os=?3, kernel=?4, arch=?5, virt=?6, cpu_name=?7,
                             cpu_cores=?8, mem_total=?9, swap_total=?10, disk_total=?11,
                             agent_version=?12, ip=?13, ipv4=?14, ipv6=?15, country_ip=?16,
                             country=CASE WHEN country_ip=?16 THEN country
                                          WHEN country_prev_ip=?16 THEN country_prev ELSE '' END,
                             country_prev_ip=CASE WHEN country_ip=?16 OR country='' THEN country_prev_ip
                                                  ELSE country_ip END,
                             country_prev=CASE WHEN country_ip=?16 OR country='' THEN country_prev
                                               ELSE country END
             WHERE id=?1",
            params![
                id,
                s("hostname"),
                s("os"),
                s("kernel"),
                s("arch"),
                s("virt"),
                s("cpu_name"),
                n("cpu_cores"),
                n("mem_total"),
                n("swap_total"),
                n("disk_total"),
                s("agent_version"),
                ip,
                s("ipv4"),
                s("ipv6"),
                source
            ],
        )?;
        let blank: bool = conn.query_row("SELECT country = '' FROM node WHERE id=?1", [id], |r| r.get(0))?;
        Ok(blank && !source.is_empty())
    }

    /// Whether the node still lacks a country for `source`: false once a lookup
    /// has landed, or once the node has moved to another address.
    pub fn country_owed(&self, id: i64, source: &str) -> Result<bool> {
        let owed = self
            .conn()
            .query_row(
                "SELECT country = '' FROM node WHERE id=?1 AND country_ip=?2",
                params![id, source],
                |r| r.get(0),
            )
            .optional()?;
        Ok(owed.unwrap_or(false))
    }

    /// Records the country a lookup returned, unless the node moved to another
    /// address while the lookup was outstanding. This is the same rule
    /// `save_facts` encodes in its `CASE`: the country belongs to the address it
    /// was asked about, so a late answer for an address the node has left is not
    /// an answer about the node. Kept apart from the panel's own writes:
    /// `update_node` never touches this column.
    pub fn set_country(&self, id: i64, cc: &str, source: &str) -> Result<()> {
        self.conn()
            .execute("UPDATE node SET country=?2 WHERE id=?1 AND country_ip=?3", params![id, cc, source])?;
        Ok(())
    }

    // ---- traffic ----

    /// Every node's counters in one query, because the node list renders a row per
    /// node and a query per node would queue the agents' writes behind it.
    ///
    /// The period counters are gated on the period they were written for. They
    /// restart lazily in `accumulate`, on the node's next report, so a node
    /// offline since before a boundary still holds the previous period's bytes on
    /// disk. This is the only reader, so the rule lives in one place.
    pub fn all_traffic(&self) -> HashMap<i64, Traffic> {
        let conn = self.conn();
        let Ok(mut stmt) = conn.prepare_cached(
            "SELECT t.node_id, t.total_rx, t.total_tx, t.month_rx, t.month_tx, t.month_start,
                    t.day_rx, t.day_tx, t.day_start, n.traffic_reset_day
                 FROM traffic t JOIN node n ON n.id = t.node_id",
        ) else {
            return HashMap::new();
        };
        let today = Local::now().date_naive();
        let day = today.to_string();
        let rows = stmt.query_map([], |r| {
            // Zero rather than absent: a theme drawing a meter requires a
            // number.
            let current = |stored: String, now: &str, rx: i64, tx: i64| {
                if stored == now {
                    (rx, tx)
                } else {
                    (0, 0)
                }
            };
            let period = period_start(today, r.get(9)?).to_string();
            let (month_rx, month_tx) = current(r.get(5)?, &period, r.get(3)?, r.get(4)?);
            let (day_rx, day_tx) = current(r.get(8)?, &day, r.get(6)?, r.get(7)?);
            Ok((
                r.get::<_, i64>(0)?,
                Traffic {
                    total_rx: r.get(1)?,
                    total_tx: r.get(2)?,
                    month_rx,
                    month_tx,
                    month_start: period,
                    day_rx,
                    day_tx,
                },
            ))
        });
        rows.map(|r| r.flatten().collect()).unwrap_or_default()
    }

    /// The traffic row as stored, without the period gate `all_traffic` applies,
    /// for tests that compare what two ways of booking left behind.
    #[cfg(test)]
    pub fn stored_traffic(&self, node_id: i64) -> Traffic {
        self.conn()
            .query_row(
                "SELECT total_rx, total_tx, month_rx, month_tx, month_start, day_rx, day_tx
                 FROM traffic WHERE node_id=?1",
                [node_id],
                |r| {
                    Ok(Traffic {
                        total_rx: r.get(0)?,
                        total_tx: r.get(1)?,
                        month_rx: r.get(2)?,
                        month_tx: r.get(3)?,
                        month_start: r.get(4)?,
                        day_rx: r.get(5)?,
                        day_tx: r.get(6)?,
                    })
                },
            )
            .expect("a traffic row")
    }

    /// Books one reading of a node's raw kernel counters into its running totals.
    ///
    /// A changed boot_id, or a counter that moved backwards, means the reading no
    /// longer continues the previous one; the total must not follow it downward.
    /// Readings arrive here about once a minute rather than with every report,
    /// which gives the same totals: see `agent_ws::file`.
    ///
    /// `at` is when the hub received the reading, and dates it for the day and
    /// billing period. A reading held back over midnight is booked after it, and
    /// still belongs to the day it arrived in.
    ///
    /// The billing reset day is read here rather than passed in: it is one join
    /// from a row this already reads, and fetching it separately would cost every
    /// booking a second acquisition of the single write connection.
    pub fn accumulate(
        &self,
        node_id: i64,
        boot_id: &str,
        (rx, tx): (i64, i64),
        at: DateTime<Local>,
    ) -> Result<Traffic> {
        let conn = self.conn();
        let (
            prev_boot,
            last_rx,
            last_tx,
            mut total_rx,
            mut total_tx,
            mut month_rx,
            mut month_tx,
            month_start,
            mut day_rx,
            mut day_tx,
            day_start,
            reset_day,
        ) = conn
            .prepare_cached(
                "SELECT t.boot_id, t.last_rx, t.last_tx, t.total_rx, t.total_tx, t.month_rx, t.month_tx,
                    t.month_start, t.day_rx, t.day_tx, t.day_start, n.traffic_reset_day
                 FROM traffic t JOIN node n ON n.id = t.node_id WHERE t.node_id=?1",
            )?
            .query_row([node_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, u32>(11)?,
                ))
            })?;

        // Only bytes this hub observed a counter climb through are booked.
        // Without a baseline under this exact boot there is nothing to subtract
        // from, and a bare reading represents the machine's entire history.
        //
        // The baseline can be missing in three ways, all handled identically. A
        // first reading has none. A reading that shrank under the same boot lost
        // one -- an interface included in the sum has disappeared -- so the
        // reading is the remainder of that history and booking it would count it
        // twice. A changed boot_id means the counters restarted, that the agent
        // now sums a different set of interfaces (it appends a digest of them,
        // so a device joining the sum is caught as well as one leaving it), or,
        // indistinguishably from here, that a second machine shares the token.
        // Realigning costs the seconds since the reboot; the alternative costs
        // hundreds of gigabytes against a total that only increases.
        let (d_rx, d_tx) = if prev_boot.is_empty() || prev_boot != boot_id {
            // Logged in either case: on a healthy node this is a reboot or the
            // agent summing a different set of interfaces, while one every few
            // seconds indicates two machines sharing a token or counted
            // interfaces coming and going. The value stays out of the log: it is
            // the agent's text.
            if !prev_boot.is_empty() {
                info!("node {node_id} reports a new boot_id; re-aligning");
            }
            (0, 0)
        } else {
            ((rx.saturating_sub(last_rx)).max(0), (tx.saturating_sub(last_tx)).max(0))
        };
        // Saturating rather than a plain `+`: the release profile disables
        // overflow checks, so a total near i64::MAX would wrap to a large
        // negative -- a lifetime figure that has decreased. Two paths reach this
        // column: a node's own counters, which arrive from another repository's
        // binary, and `set_traffic`, through which the panel writes corrections.
        // Clamping here covers both rather than each caller separately.
        total_rx = total_rx.saturating_add(d_rx);
        total_tx = total_tx.saturating_add(d_tx);
        month_rx = month_rx.saturating_add(d_rx);
        month_tx = month_tx.saturating_add(d_tx);
        day_rx = day_rx.saturating_add(d_rx);
        day_tx = day_tx.saturating_add(d_tx);

        // Both boundaries are calendar dates -- the day a provider resets an
        // allowance, the day a person means by "today" -- so both follow the
        // hub's local timezone rather than UTC.
        //
        // Never dated before a period the row already carries. The panel stamps
        // the current period with a correction, which a reading held back from
        // before the boundary would otherwise read as a new period and discard.
        // A date later than the stamp is used as it is, so a changed reset day
        // still takes effect. A stamp later than today came from a clock since
        // stepped back and is not honoured: it would hold both counters in that
        // period, which the read side answers as zero, until the date caught up.
        let (date, today) = (at.date_naive(), Local::now().date_naive());
        let dated = |stored: &str| {
            stored
                .parse::<NaiveDate>()
                .ok()
                .filter(|stamp| *stamp <= today)
                .map_or(date, |stamp| stamp.max(date))
        };
        let period = period_start(dated(&month_start), reset_day).to_string();
        if month_start != period {
            // A new billing period restarts the month counter but not the total.
            month_rx = d_rx;
            month_tx = d_tx;
        }
        let day = dated(&day_start).to_string();
        if day_start != day {
            day_rx = d_rx;
            day_tx = d_tx;
        }

        conn.prepare_cached(
            "UPDATE traffic SET boot_id=?2, last_rx=?3, last_tx=?4, total_rx=?5, total_tx=?6,
                            month_rx=?7, month_tx=?8, month_start=?9, day_rx=?10, day_tx=?11,
                            day_start=?12 WHERE node_id=?1",
        )?
        .execute(params![
            node_id, boot_id, rx, tx, total_rx, total_tx, month_rx, month_tx, period, day_rx, day_tx, day
        ])?;
        Ok(Traffic { total_rx, total_tx, month_rx, month_tx, month_start: period, day_rx, day_tx })
    }

    /// Allows the panel to correct a total, for example after moving a node to
    /// new hardware.
    ///
    /// The corrected month figures are stamped with the current period; otherwise
    /// they would belong to whichever period the row still held, `all_traffic`
    /// would read them back as zero, and the node's next report would restart the
    /// counter and discard the correction.
    ///
    /// False when no node has this id.
    pub fn set_traffic(&self, node_id: i64, p: &TrafficPatch) -> Result<bool> {
        let conn = self.conn();
        let Some(reset_day): Option<u32> = conn
            .query_row("SELECT traffic_reset_day FROM node WHERE id=?1", [node_id], |r| r.get(0))
            .optional()?
        else {
            return Ok(false);
        };
        let period = period_start(Local::now().date_naive(), reset_day).to_string();
        conn.execute(
            "UPDATE traffic SET total_rx=COALESCE(?2,total_rx), total_tx=COALESCE(?3,total_tx),
                 month_rx=COALESCE(?4,CASE WHEN month_start=?6 THEN month_rx ELSE 0 END),
                 month_tx=COALESCE(?5,CASE WHEN month_start=?6 THEN month_tx ELSE 0 END), month_start=?6
             WHERE node_id=?1",
            params![node_id, p.total_rx, p.total_tx, p.month_rx, p.month_tx, period],
        )?;
        Ok(true)
    }

    // ---- metrics ----

    pub fn insert_metric(&self, node_id: i64, ts: i64, m: &serde_json::Value) -> Result<()> {
        let f = |k: &str| m.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
        let n = |k: &str| m.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        self.conn()
            .prepare_cached(
                "INSERT OR REPLACE INTO metric
               (node_id, ts, cpu, mem_used, swap_used, disk_used, net_rx, net_tx, tcp, udp, procs,
                net_rx_max, net_tx_max)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            )?
            .execute(params![
                node_id,
                ts,
                f("cpu"),
                n("mem_used"),
                n("swap_used"),
                n("disk_used"),
                n("net_rx"),
                n("net_tx"),
                n("tcp"),
                n("udp"),
                n("procs"),
                n("net_rx_max"),
                n("net_tx_max")
            ])?;
        Ok(())
    }

    /// History for one node, thinned to one sample every `step` seconds.
    ///
    /// Bucketed rather than filtered on a multiple of `step`: rows normally land
    /// on the minute, but nothing enforces it, and a filter would return nothing
    /// for a stamp falling between grid lines.
    ///
    /// Averaged over the bucket rather than sampled from it. Keeping one row per
    /// bucket would reintroduce the 1/60 sampling the write side already rejects:
    /// the seven-day window integrated to 53.69 GB against the 27.52 GB the
    /// minutes hold, while averaging gives 28.02 GB, matching the accumulator.
    ///
    /// `swap_used`, `tcp`, `udp` and `procs` are stored but not returned, as
    /// nothing draws them from history. The columns are retained deliberately;
    /// `load1` was the fifth and has been removed, see `migrate_to_2`.
    ///
    /// The stamp is the bucket's start rather than a row inside it, so every
    /// series lands on one grid and the probe rows below can be shared.
    ///
    /// `net_rx_max` and `net_tx_max` are the bucket's highest rather than its
    /// mean, since a maximum of maxima loses nothing: a week's window peaks at
    /// the same rate as the minute that reached it. Each row counts as at least
    /// its own mean: rows predating the column hold 0, and the mean, timed by
    /// the hub's arrivals rather than the agent's clock, can edge past the
    /// agent's own rates by the network's jitter.
    pub fn metrics(&self, node_id: i64, since: i64, step: i64) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT (MIN(ts)/?3)*?3, AVG(cpu), CAST(AVG(mem_used) AS INTEGER),
                    CAST(AVG(disk_used) AS INTEGER),
                    CAST(AVG(net_rx) AS INTEGER), CAST(AVG(net_tx) AS INTEGER),
                    MAX(MAX(net_rx, net_rx_max)), MAX(MAX(net_tx, net_tx_max))
             FROM metric WHERE node_id=?1 AND ts>=?2 GROUP BY ts/?3 ORDER BY ts/?3",
        )?;
        let rows = stmt.query_map(params![node_id, since, step], |r| {
            Ok(serde_json::json!({
                "ts": r.get::<_, i64>(0)?, "cpu": r.get::<_, f64>(1)?,
                "mem_used": r.get::<_, i64>(2)?, "disk_used": r.get::<_, i64>(3)?,
                "net_rx": r.get::<_, i64>(4)?, "net_tx": r.get::<_, i64>(5)?,
                "net_rx_max": r.get::<_, i64>(6)?, "net_tx_max": r.get::<_, i64>(7)?,
            }))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Drops history beyond the retention window. Traffic totals live in their
    /// own table precisely so history can be pruned freely.
    pub fn prune(&self, keep_days: i64) -> Result<usize> {
        let cutoff = Utc::now().timestamp() - keep_days * 86_400;
        let conn = self.conn();
        let a = conn.execute("DELETE FROM metric WHERE ts < ?1", [cutoff])?;
        let b = conn.execute("DELETE FROM ping_record WHERE ts < ?1", [cutoff])?;
        // 流量采样独立保留 30 天：概览的 24h 走势与排行只用最近窗口。8 天
        // 起由 compact_traffic_samples 压成小时行，这里只负责把 30 天外的
        // 行（含压缩行）清掉。
        let sample_cutoff = Utc::now().timestamp() - 30 * 86_400;
        let c = conn.execute("DELETE FROM traffic_samples WHERE ts < ?1", [sample_cutoff])?;
        Ok(a + b + c)
    }

    /// agent_jobs 审计只留 30 天：推送对账的排障窗口。该表只进不出，风暴期
    /// （如 relay 对账死循环修复前）一天能写 1400 行，不清就无限涨。
    pub fn prune_agent_jobs(&self, keep_days: i64) -> Result<usize> {
        let cutoff = Utc::now().timestamp() - keep_days * 86_400;
        Ok(self.conn().execute("DELETE FROM agent_jobs WHERE created_at < ?1", [cutoff])?)
    }

    // ---- ping ----

    pub fn ping_tasks(&self) -> Result<Vec<PingTask>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT id, name, target, interval, auto_join FROM ping_task ORDER BY sort, id")?;
        let tasks: Vec<PingTask> = stmt
            .query_map([], |r| {
                Ok(PingTask {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    target: r.get(2)?,
                    interval: r.get(3)?,
                    nodes: Vec::new(),
                    auto_join: r.get(4)?,
                    base: None,
                })
            })?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        let mut stmt = conn.prepare("SELECT node_id FROM ping_node WHERE task_id=?1")?;
        tasks
            .into_iter()
            .map(|mut t| {
                t.nodes = stmt.query_map([t.id], |r| r.get(0))?.collect::<Result<_, _>>()?;
                Ok(t)
            })
            .collect()
    }

    /// The maximum number of probes one node may be assigned.
    ///
    /// The agent enforces the same limit: `MAX_PING_TASKS` in that repository
    /// caps the list it will run, since a compromised or buggy hub could
    /// otherwise ask a node for hundreds of outbound connects per second. That
    /// cap is a defence and remains, but on its own it truncates silently,
    /// leaving one line in the node's journal while the hub continues pushing
    /// probes that never run and drawing charts that stay empty.
    ///
    /// The hub knows the total, so the hub issues the refusal. The two must stay
    /// in step; the agent's copy is the backstop rather than the message.
    pub const MAX_PROBES_PER_NODE: i64 = 64;

    /// The shortest probe interval in seconds. The agent clamps to the same
    /// floor, so together with [`Self::MAX_PROBES_PER_NODE`] it bounds how many
    /// results an honest node can send.
    pub const MIN_PROBE_INTERVAL: i64 = 5;

    /// Replaces the assignments wholesale, or with `base` applies only what
    /// changed from it. Either way in one transaction: failing between the
    /// deletes and the inserts would unassign nodes from a probe the panel still
    /// lists them under.
    pub fn save_ping_task(&self, t: &PingTask) -> Result<i64> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let id = if t.id > 0 {
            let updated = tx.execute(
                "UPDATE ping_task SET name=?2, target=?3, interval=?4, auto_join=?5 WHERE id=?1",
                params![t.id, t.name, t.target, t.interval, t.auto_join],
            )?;
            // Deleted from another session. Without this the first assignment
            // would fail on the task's foreign key and be reported against a
            // node, or, with none, the save would report success.
            if updated == 0 {
                refuse!("监控不存在，可能已被删除");
            }
            t.id
        } else {
            // At the end, as in `create_node`.
            tx.execute(
                "INSERT INTO ping_task (name, target, interval, auto_join, sort)
                 VALUES (?1,?2,?3,?4,(SELECT COALESCE(MAX(sort),-1)+1 FROM ping_task))",
                params![t.name, t.target, t.interval, t.auto_join],
            )?;
            tx.last_insert_rowid()
        };
        let added: Vec<i64> = match &t.base {
            Some(base) if t.id > 0 => {
                for node in base.iter().filter(|n| !t.nodes.contains(n)) {
                    tx.execute("DELETE FROM ping_node WHERE task_id=?1 AND node_id=?2", params![id, node])?;
                }
                t.nodes.iter().filter(|n| !base.contains(n)).copied().collect()
            }
            _ => {
                tx.execute("DELETE FROM ping_node WHERE task_id=?1", [id])?;
                t.nodes.clone()
            }
        };
        for node in &added {
            // OR IGNORE covers a node that joined while the editor was open and
            // was then ticked. It does not cover the foreign key, which remains
            // the check; naming the node turns SQLite's "FOREIGN KEY constraint
            // failed" into something the panel can show.
            tx.execute(
                "INSERT OR IGNORE INTO ping_node (task_id, node_id) VALUES (?1,?2)",
                params![id, node],
            )
            .map_err(|e| match e.sqlite_error_code() {
                Some(rusqlite::ErrorCode::ConstraintViolation) => {
                    anyhow::Error::from(e).context(crate::Shown(format!("节点 {node} 不存在，可能已被删除")))
                }
                _ => e.into(),
            })?;
        }
        // Queried from the table after the rows are in rather than counted from
        // the request: an update changes this task's own assignments, so
        // arithmetic on the way in would have to subtract them again. The
        // transaction makes this atomic with the write, and bailing here rolls it
        // back.
        // By name: the panel identifies nodes by name and never shows an id.
        let crowded: Option<String> = tx
            .query_row(
                "SELECT n.name FROM ping_node p JOIN node n ON n.id = p.node_id
                 GROUP BY p.node_id HAVING COUNT(*) > ?1 LIMIT 1",
                [Self::MAX_PROBES_PER_NODE],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(node) = crowded {
            refuse!(
                "节点「{node}」会被分配超过 {} 个探测任务，agent 最多只跑这么多，多出来的会被静默丢掉",
                Self::MAX_PROBES_PER_NODE
            );
        }
        // The next node created receives every auto-joining probe at once.
        let joining: i64 =
            tx.query_row("SELECT COUNT(*) FROM ping_task WHERE auto_join", [], |r| r.get(0))?;
        if joining > Self::MAX_PROBES_PER_NODE {
            refuse!("新节点会自动加入 {joining} 个探测任务，agent 最多只跑 {} 个", Self::MAX_PROBES_PER_NODE);
        }
        tx.commit()?;
        Ok(id)
    }

    /// Deletes a probe and the results filed under it.
    ///
    /// `ping_record` carries no foreign key -- it is WITHOUT ROWID and keyed for
    /// the chart query -- so it is cleared explicitly, as in `delete_node`.
    /// SQLite reassigns a deleted probe's id to the next one created, and the
    /// chart selects on `task_id IN (assignments for this node)`: without this
    /// the new probe would draw the removed one's latency under its own name,
    /// with its timeouts folded into the loss figure.
    ///
    /// The delete is a scan -- the key begins at `node_id` -- comparable in cost
    /// to `prune`, for an action taken manually a few times a year.
    pub fn delete_ping_task(&self, id: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM ping_record WHERE task_id = ?1", [id])?;
        conn.execute("DELETE FROM ping_task WHERE id=?1", [id])?;
        Ok(())
    }

    /// The task list pushed to one agent.
    ///
    /// Ordered, because the agent keeps the first [`Self::MAX_PROBES_PER_NODE`]
    /// as its backstop against a hub requesting hundreds. Unordered, a list at
    /// that boundary could yield a different subset on each push, restarting half
    /// the timers each time; `save_ping_task` prevents reaching that boundary,
    /// and this makes the backstop deterministic should a database arrive there
    /// by another route.
    ///
    /// By id rather than the panel's `sort`, so reordering in the panel changes
    /// nothing an agent holds and needs no push.
    pub fn ping_tasks_for(&self, node_id: i64) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT t.id, t.target, t.interval FROM ping_task t
             JOIN ping_node n ON n.task_id = t.id WHERE n.node_id = ?1 ORDER BY t.id",
        )?;
        let rows = stmt.query_map([node_id], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?, "target": r.get::<_, String>(1)?,
                "interval": r.get::<_, i64>(2)?
            }))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Probe names keyed by id, for labelling one node's latency chart. Names
    /// only: targets and node assignments remain behind `Admin`.
    ///
    /// Restricted to the probes assigned to that node, the only ones its chart
    /// has samples to label. A probe name is operator-supplied text that
    /// routinely carries a hostname or a customer, and the rest of the table
    /// belongs to nodes this caller may not be able to see.
    pub fn ping_task_names(&self, node_id: i64) -> Result<serde_json::Value> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, name FROM ping_task WHERE id IN (SELECT task_id FROM ping_node WHERE node_id=?1)",
        )?;
        let rows = stmt.query_map([node_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        let mut names = serde_json::Map::new();
        for row in rows {
            let (id, name) = row?;
            names.insert(id.to_string(), serde_json::json!(name));
        }
        Ok(serde_json::Value::Object(names))
    }

    /// Files a node's probe results as `(task_id, ts, latency)`, each only under a
    /// probe this node is assigned. A result for anything else is dropped rather
    /// than treated as an error, since the agent can do nothing useful with the
    /// distinction.
    ///
    /// One transaction for the batch: the session gathers a minute of results and
    /// files them together, since each commit writes at least one page.
    ///
    /// The assignment is tested inside the statement because that is the only
    /// place it is atomic with the write: `ping_record` carries no foreign key,
    /// being WITHOUT ROWID and keyed for the chart query. Two cases arrive
    /// without an assignment. A result already in flight when the panel deleted
    /// its probe, which would otherwise land after `delete_ping_task` swept the
    /// history and be inherited by whichever probe SQLite assigns the id to next.
    /// And a node token in the wrong hands: `task_id` is chosen by the reporter,
    /// so without the test the rows it could create would be unbounded.
    ///
    /// The chart's `task_id IN (assignments)` filter hides both afterwards, but
    /// does not prevent the write, its storage, or the id being reused.
    pub fn insert_pings(&self, node_id: i64, results: &[(i64, i64, i64)]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT OR REPLACE INTO ping_record (node_id, task_id, ts, latency)
                 SELECT ?1, ?2, ?3, ?4
                 WHERE EXISTS (SELECT 1 FROM ping_node WHERE task_id = ?2 AND node_id = ?1)",
            )?;
            for (task_id, ts, latency) in results {
                insert.execute(params![node_id, task_id, ts, latency])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Probe results for one node, one sample per probe per `step` seconds: the
    /// bucket's median round trip, its range, and the proportion lost.
    ///
    /// These stamps fall wherever the probe finished rather than on a minute, so
    /// the thinning buckets them instead of matching a multiple, as in `metrics`
    /// above. This is the larger half of that response, since a probe reports far
    /// more often than once a minute.
    ///
    /// [`PING_ROWS`] returns rows in time order, so a bucket is complete the
    /// moment the next opens and only one is held at a time -- at most the probes
    /// assigned to the node times the results one bucket spans.
    ///
    /// Returns the buckets and, alongside them, the proportion of the whole
    /// window each probe lost. The latter cannot be recovered from the former:
    /// [`close_bucket`] divides within each bucket and keeps only the quotient,
    /// so averaging those percentages would weight a bucket holding one sample
    /// equally with one holding twelve. The buckets are necessarily unequal --
    /// the window's first and last are partial by construction, and a probe that
    /// starts, stops, loses its node or skips a round produces more. The
    /// denominators are available only here, in the pass that already reads every
    /// row. Probes that lost nothing are omitted, as `loss` is per bucket.
    pub fn ping_records(
        &self,
        node_id: i64,
        since: i64,
        step: i64,
    ) -> Result<(Vec<serde_json::Value>, serde_json::Value)> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(PING_ROWS)?;
        let mut rows = stmt.query(params![node_id, since, step])?;
        let mut out = Vec::new();
        // Per probe in the bucket being filled: what answered, and how many did
        // not.
        let mut open: Vec<(i64, Vec<i64>, i64)> = Vec::new();
        // Per probe across the whole window: how many were lost, out of how many.
        // Folded in the same pass rather than queried from SQLite a second time,
        // for the same reason the bucket fold itself is in Rust.
        let mut totals: HashMap<i64, (i64, i64)> = HashMap::new();
        let mut bucket = 0;
        while let Some(row) = rows.next()? {
            let (b, task, latency) = (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?);
            if b != bucket {
                close_bucket(&mut out, &mut open, bucket * step);
                bucket = b;
            }
            let seen = totals.entry(task).or_insert((0, 0));
            seen.1 += 1;
            let probe = match open.iter().position(|(id, ..)| *id == task) {
                Some(at) => &mut open[at],
                None => {
                    open.push((task, Vec::new(), 0));
                    open.last_mut().expect("just pushed")
                }
            };
            // A timeout is stored as -1: excluded from the median and counted
            // instead.
            if latency < 0 {
                probe.2 += 1;
                seen.0 += 1;
            } else {
                probe.1.push(latency);
            }
        }
        close_bucket(&mut out, &mut open, bucket * step);
        // Probe by probe in the panel's order, each probe's rows still in time
        // order. Themes take their series, colours and legend from the order in
        // which probes first appear; bucket by bucket, that would be whichever
        // probe happened to answer inside the window's partial first bucket.
        let rank: HashMap<i64, usize> = conn
            .prepare_cached("SELECT id FROM ping_task ORDER BY sort, id")?
            .query_map([], |r| r.get(0))?
            .enumerate()
            .map(|(i, id)| id.map(|id| (id, i)))
            .collect::<Result<_, _>>()?;
        // Sorted after releasing the connection the agents write through. A
        // probe missing from the rank, which the assignment filter in
        // `PING_ROWS` rules out today, goes last rather than taking the first
        // colour.
        drop(rows);
        drop(stmt);
        drop(conn);
        out.sort_by_cached_key(|row| {
            row["task_id"].as_i64().and_then(|id| rank.get(&id).copied()).unwrap_or(usize::MAX)
        });
        // Unrounded: the caller decides how to render it, and rounding here would
        // turn 0.14% into the 0% that denotes no loss at all.
        let loss: serde_json::Map<String, serde_json::Value> = totals
            .into_iter()
            .filter(|(_, (lost, _))| *lost > 0)
            .map(|(task, (lost, samples))| {
                (task.to_string(), serde_json::json!(100.0 * lost as f64 / samples as f64))
            })
            .collect();
        Ok((out, serde_json::Value::Object(loss)))
    }

    // ---- the database file itself ----

    /// The file this connection is open on, empty for `:memory:`.
    pub fn file(&self) -> String {
        main_file(&self.conn())
    }

    /// The retention window used by both `prune` and the data page. Stored as
    /// text by the settings form, so a missing or unparsable value falls back to
    /// the default rather than erroring.
    pub fn retention_days(&self) -> i64 {
        self.get("retention_days").and_then(|v| v.parse::<i64>().ok()).unwrap_or(7).clamp(1, 3_650)
    }

    /// What the panel's data page reads: how much space the file occupies, how
    /// much of that is free pages awaiting a `VACUUM`, and how far back the
    /// history actually reaches.
    ///
    /// `oldest` against `retention` is the one pair here that can indicate a
    /// fault: history older than the window means `prune` has not been running.
    pub fn stats(&self) -> Result<serde_json::Value> {
        // Before acquiring the connection: `conn()` returns a guard on a plain
        // Mutex, and `retention_days` acquires the same one.
        let retention = self.retention_days();
        let conn = self.conn();
        let file = main_file(&conn);
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let free_pages: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        // Both are pruned at the same cutoff, so the earlier of the two marks
        // where history begins. A full scan of each, which the counts below
        // already incur.
        let oldest: Option<i64> = conn.query_row(
            "SELECT MIN(ts) FROM (SELECT MIN(ts) AS ts FROM metric UNION ALL SELECT MIN(ts) FROM ping_record)",
            [],
            |r| r.get(0),
        )?;
        let mut rows = serde_json::Map::new();
        for table in TABLES {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
            rows.insert(table.to_owned(), serde_json::json!(n));
        }
        Ok(serde_json::json!({
            "path": file,
            "size": bytes_of(&file),
            "wal": bytes_of(&format!("{file}-wal")),
            "free": free_pages * page_size,
            "oldest": oldest,
            "retention": retention,
            "rows": rows,
        }))
    }

    /// Writes a consistent copy of the live database to `dest`, which must not
    /// already exist.
    ///
    /// `VACUUM INTO` is SQLite's own mechanism for this: one statement, a single
    /// read transaction, and a compacted copy with free pages already dropped. It
    /// reads the whole file, so the caller runs it off the runtime -- every other
    /// statement here is sub-millisecond, this one is not.
    pub fn backup_into(&self, dest: &str) -> Result<()> {
        // A second connection to the same file. `VACUUM INTO` only reads, and WAL
        // allows it to read a consistent snapshot while the agents continue
        // writing through the first -- exporting is the one heavy operation here
        // that need not block them. A fresh connection inherits none of the
        // PRAGMAs in SCHEMA, so the busy timeout must be set again or a
        // checkpoint racing this read returns SQLITE_BUSY immediately.
        let reader = Connection::open(self.file())?;
        reader.busy_timeout(std::time::Duration::from_secs(5))?;
        reader.execute("VACUUM INTO ?1", [dest])?;
        // The copy is the credential store in one portable file: node tokens in
        // the clear, the GitHub secret, the password hash. SQLite creates it
        // under the umask, which at the usual 022 is world-readable.
        own_only(dest);
        Ok(())
    }

    /// Rebuilds the file, reclaiming the pages deleted history left behind.
    /// Returns the bytes recovered.
    ///
    /// SQLite's constraints on `VACUUM`, and why they hold here: it cannot run
    /// inside a transaction or with a live statement on the connection (there is
    /// one connection, and this call owns it); it requires roughly as much free
    /// disk as the database itself, and a failure rolls back leaving the original
    /// untouched; and it can renumber rowids, which nothing here keys on, since
    /// `metric` and `ping_record` are WITHOUT ROWID and every other table
    /// declares its own primary key.
    ///
    /// In WAL mode the rewrite lands in the WAL first, so without the checkpoint
    /// the file on disk grows rather than shrinking.
    pub fn vacuum(&self) -> Result<i64> {
        let conn = self.conn();
        let file = main_file(&conn);
        let before = on_disk(&file);
        conn.execute_batch("VACUUM")?;
        // Best effort: the space is already reclaimed within the database, and a
        // checkpoint that cannot run now does not constitute a failed vacuum.
        let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        Ok((before - on_disk(&file)).max(0))
    }

    /// What a file must satisfy before a single page of it is copied over the
    /// live database. Restore is the one operation here that destroys data, and
    /// the file behind it originates from a disk this hub knows nothing about.
    ///
    /// **Writes to `src`.** The migrations an older backup requires run here, on
    /// the upload, rather than after copying: everything that can fail does so
    /// while the live database is still untouched. The caller owns that file and
    /// deletes it in either case.
    pub fn check_backup(&self, src: &str) -> Result<()> {
        const NOT_A_BACKUP: &str = "这不是 hub 导出的备份文件";
        // Read-write rather than read-only: a plain copy of a running hub's
        // database is in WAL mode, and SQLite cannot open such a file read-only
        // without its -shm companion.
        let candidate = Connection::open(src)?;
        let health: String = candidate
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .context(crate::Shown(NOT_A_BACKUP.into()))?;
        if health != "ok" {
            info!("uploaded backup fails integrity_check: {health}");
            refuse!("备份文件已损坏，数据库完整性检查没有通过");
        }
        // Pages are copied verbatim, so whatever schema the file carries becomes
        // the schema this hub runs its statements against. A view or trigger
        // where a table belongs would route every subsequent write through
        // externally supplied code.
        let plotted: i64 = candidate.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('view', 'trigger')",
            [],
            |r| r.get(0),
        )?;
        if plotted > 0 {
            refuse!("文件里有视图或触发器，不是 hub 导出的备份");
        }
        for table in TABLES {
            let found: i64 = candidate.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )?;
            if found == 0 {
                refuse!("{NOT_A_BACKUP}：缺少 {table} 表");
            }
        }
        let version: i64 = candidate.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            refuse!("备份来自更新版本的 hub（数据库版本 {version}，这台只认到 {SCHEMA_VERSION}），先升级 hub 再恢复");
        }
        // The online backup API refuses a page size change while the destination
        // is in WAL mode; an explicit message is clearer than SQLITE_READONLY.
        let theirs: i64 = candidate.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let ours: i64 = self.conn().query_row("PRAGMA page_size", [], |r| r.get(0))?;
        if theirs != ours {
            refuse!("备份的页大小是 {theirs} 字节，这台 hub 是 {ours} 字节，无法恢复");
        }
        // Brought up to this build's schema here, on the upload. Run after the
        // copy instead, a failed migration would leave the hub on a database it
        // could not use while reporting a failure to the panel -- the one
        // arrangement in which the restore has failed and the original data is
        // also gone.
        migrate(&candidate, version)?;
        // The migration lands in a -wal beside a backup taken from a running hub.
        // Checkpointed here so the copy below reads a single file.
        let _ = candidate.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));

        // Table names are not a schema. Pages are copied verbatim, so the columns
        // the file carries become the ones this hub's statements run against, and
        // eight correctly named tables holding the wrong columns pass every gate
        // above while leaving the database unusable.
        //
        // Compared against a database this build creates for itself, so there is
        // no second column list to keep in step with `SCHEMA`. Names are compared
        // as sets rather than as stored DDL: a migrated old backup reaches the
        // same columns through `ALTER TABLE`, whose text never matches a fresh
        // `CREATE TABLE`. Extra columns are ignored.
        let reference = Connection::open_in_memory()?;
        reference.execute_batch(SCHEMA)?;
        migrate(&reference, SCHEMA_VERSION)?;
        for table in TABLES {
            let want = columns_of(&reference, table)?;
            let got = columns_of(&candidate, table)?;
            let mut missing: Vec<&str> = want.difference(&got).map(String::as_str).collect();
            if !missing.is_empty() {
                missing.sort_unstable();
                refuse!("{NOT_A_BACKUP}：{table} 表缺少字段 {}", missing.join("、"));
            }
        }
        Ok(())
    }

    /// Copies a checked backup over the live database page by page through
    /// SQLite's online backup API: the destination retains its file, permissions
    /// and journal mode, and a partial failure rolls back rather than leaving
    /// half a database behind.
    ///
    /// Call [`Db::check_backup`] first, as it is what brings `src` to this
    /// build's schema; the copy is then the last step and nothing after it can
    /// fail. Like the other two, this reads and writes the whole file and belongs
    /// off the runtime.
    pub fn restore_from(&self, src: &str) -> Result<()> {
        let mut conn = self.conn();
        conn.restore(rusqlite::MAIN_DB, src, None::<fn(rusqlite::backup::Progress)>)?;
        Ok(())
    }

    // ---- sessions ----

    pub fn create_session(
        &self,
        token_hash: &str,
        expires_at: i64,
        ip: &str,
        user_agent: &str,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO session (token_hash, expires_at, ip, user_agent) VALUES (?1, ?2, ?3, ?4)",
            params![token_hash, expires_at, ip, user_agent],
        )?;
        Ok(())
    }

    pub fn session_valid(&self, token_hash: &str) -> bool {
        self.conn()
            .query_row(
                "SELECT 1 FROM session WHERE token_hash=?1 AND expires_at > ?2",
                params![token_hash, Utc::now().timestamp()],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    /// Live sessions, newest first. Expired rows are filtered here rather than
    /// left to `expire_sessions`, which sweeps only once an hour.
    pub fn sessions(&self) -> Result<Vec<SessionRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT token_hash, expires_at, ip, user_agent FROM session WHERE expires_at > ?1 ORDER BY expires_at DESC",
        )?;
        let rows = stmt
            .query_map([Utc::now().timestamp()], |r| {
                Ok(SessionRow {
                    token_hash: r.get(0)?,
                    expires_at: r.get(1)?,
                    ip: r.get::<_, String>(2).unwrap_or_default(),
                    user_agent: r.get::<_, String>(3).unwrap_or_default(),
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// 下线除当前会话外的全部登录（「退出所有设备」）。当前会话必须保留：
    /// 把自己也踢了等于当场登出，与按钮语义不符。
    pub fn drop_other_sessions(&self, keep_hash: &str) -> Result<usize> {
        let n = self.conn().execute("DELETE FROM session WHERE token_hash != ?1", [keep_hash])?;
        Ok(n)
    }

    pub fn drop_session(&self, token_hash: &str) -> Result<()> {
        self.conn().execute("DELETE FROM session WHERE token_hash=?1", [token_hash])?;
        Ok(())
    }

    /// Replaces the admin password hash and signs every session out, both or
    /// neither: a reset that stored the hash and then failed would report failure
    /// while the old password no longer works.
    pub fn replace_password(&self, hash: &str) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO setting (key, value) VALUES ('admin_password_hash', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [hash],
        )?;
        tx.execute("DELETE FROM session", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Invalidates every login. Used after a restore, which would otherwise
    /// revive every session the backup holds.
    pub fn drop_all_sessions(&self) -> Result<()> {
        self.conn().execute("DELETE FROM session", [])?;
        Ok(())
    }

    pub fn expire_sessions(&self) -> Result<()> {
        self.conn().execute("DELETE FROM session WHERE expires_at <= ?1", [Utc::now().timestamp()])?;
        Ok(())
    }
}

/// Turns one finished bucket into a row per probe, stamped with the bucket's
/// start so every series lands on the same grid.
///
/// Median rather than mean: one SYN retransmit is tens of milliseconds and would
/// drag a mean, and it is the reading that is wrong rather than the link.
///
/// `latency` is null when an entire bucket timed out. `loss` is the percentage
/// that did, included only when non-zero -- a healthy day is 2,880 rows, and
/// `"loss":0` on each would add 29 kB of nothing. Rounded up, so that the absence
/// of a `loss` key means no timeouts occurred: truncating would report a bucket
/// that lost 1 of 180 as clean.
fn close_bucket(out: &mut Vec<serde_json::Value>, open: &mut Vec<(i64, Vec<i64>, i64)>, ts: i64) {
    for (task, mut answered, lost) in open.drain(..) {
        answered.sort_unstable();
        let middle = match answered.len() {
            0 => None,
            n if n % 2 == 1 => Some(answered[n / 2]),
            n => Some((answered[n / 2 - 1] + answered[n / 2]) / 2),
        };
        let mut row = serde_json::json!({"task_id": task, "ts": ts, "latency": middle});
        // Only when the bucket actually varied. At the hour and six-hour windows a
        // bucket holds one sample, and a band would be a zero-height ribbon under
        // every line.
        if let (Some(lo), Some(hi)) = (answered.first(), answered.last()) {
            if hi > lo {
                row["band"] = serde_json::json!([lo, hi]);
            }
        }
        if lost > 0 {
            let total = answered.len() as i64 + lost;
            row["loss"] = ((100 * lost + total - 1) / total).into();
        }
        out.push(row);
    }
}

fn row_to_node(r: &rusqlite::Row<'_>) -> Node {
    let s = |i: &str| r.get::<_, String>(i).unwrap_or_default();
    let n = |i: &str| r.get::<_, i64>(i).unwrap_or(0);
    Node {
        dns_name: s("dns_name"),
        dns_ip: s("dns_ip"),
        purchase_url: s("purchase_url"),
        id: n("id"),
        name: s("name"),
        public: r.get::<_, bool>("public").unwrap_or(true),
        sort: n("sort"),
        price: r.get::<_, f64>("price").unwrap_or(0.0),
        currency: s("currency"),
        billing_cycle: s("billing_cycle"),
        expires_at: r.get::<_, Option<String>>("expires_at").unwrap_or(None),
        remark: s("remark"),
        traffic_limit: n("traffic_limit"),
        traffic_mode: s("traffic_mode"),
        traffic_reset_day: n("traffic_reset_day") as u32,
        hostname: s("hostname"),
        os: s("os"),
        kernel: s("kernel"),
        arch: s("arch"),
        virt: s("virt"),
        cpu_name: s("cpu_name"),
        cpu_cores: n("cpu_cores"),
        mem_total: n("mem_total"),
        swap_total: n("swap_total"),
        disk_total: n("disk_total"),
        agent_version: s("agent_version"),
        ip: s("ip"),
        ipv4: s("ipv4"),
        ipv6: s("ipv6"),
        country: s("country"),
        country_pin: s("country_pin"),
        group: s("group_name"),
        ipv4_pin: s("ipv4_pin"),
        ipv6_pin: s("ipv6_pin"),
        last_seen: n("last_seen"),
        notify: n("notify") != 0,
        down_since: n("down_since"),
        token: s("token"),
    }
}

/// Start of the billing period containing `today`, given a reset day of month.
/// A reset day past the end of a short month lands on that month's last day.
pub fn period_start(today: NaiveDate, reset_day: u32) -> NaiveDate {
    let day = reset_day.clamp(1, 31);
    let clamped = |y: i32, m: u32| {
        let last =
            NaiveDate::from_ymd_opt(if m == 12 { y + 1 } else { y }, if m == 12 { 1 } else { m + 1 }, 1)
                .unwrap()
                .pred_opt()
                .unwrap()
                .day();
        NaiveDate::from_ymd_opt(y, m, day.min(last)).unwrap()
    };
    let this = clamped(today.year(), today.month());
    if today >= this {
        this
    } else if today.month() == 1 {
        clamped(today.year() - 1, 12)
    } else {
        clamped(today.year(), today.month() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        Db::open(":memory:").unwrap()
    }

    /// 2026-10-26/27 三次 hub 整体冻结的根因回归：take_mcp_code 曾在首个
    /// conn 守卫存活期间二次 self.conn() 取锁，Db 的 Mutex 非重入——授权码
    /// 有效的 token 交换必然自死锁，单 worker 生产环境即整站冻结。conn()
    /// 的重入断言会让此类回归当场 panic（测试直接失败，无需限时观测）。
    #[test]
    fn take_mcp_code_consumes_valid_code_without_deadlock() {
        let db = db();
        db.save_mcp_code("h", "cid", "http://127.0.0.1:1/cb", "c", "S256", 1, 9).unwrap();
        let first = db.take_mcp_code("h", 0).unwrap();
        let second = db.take_mcp_code("h", 0).unwrap();
        assert!(first.is_some(), "有效授权码必须能取走");
        assert!(second.is_none(), "授权码一次性，再取必须为空");
    }

    /// 重入断言自证：同线程二次 conn() 必须立即 panic 而非永久挂死。
    #[test]
    #[should_panic(expected = "Db::conn 同线程重入")]
    fn conn_reentry_on_same_thread_panics_instead_of_deadlocking() {
        let db = db();
        let _outer = db.conn();
        let _inner = db.conn();
    }

    /// 跨实例嵌套持锁合法（不同的锁，an_upgraded_release 的比对语句就靠它），
    /// 不得被重入断言误伤。
    #[test]
    fn conn_nested_across_different_dbs_is_fine() {
        let a = db();
        let b = db();
        let ga = a.conn();
        let gb = b.conn();
        ga.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).unwrap();
        gb.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).unwrap();
    }

    /// 配额记账：一次性总量包持续累加并在越过额度时报一次边沿；每月重置
    /// 在进入新自然月的首次记账清零重计。
    /// 迁移 42：存量 kv 里配好的 Telegram/Webhook 升级成渠道实例，事件路由到
    /// 全部渠道；模板设置随渠道走。
    #[test]
    fn migrate_42_promotes_kv_channels_and_routes_everything() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE setting (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO setting (key, value) VALUES
               ('notify_telegram_token', '123456:AA-b_c'),
               ('notify_telegram_chat', '42'),
               ('notify_telegram_text', '[{{site}}] {{title}}'),
               ('notify_webhook_url', 'https://hooks.example/h'),
               ('notify_webhook_headers', 'Authorization: Bearer x');
             CREATE TABLE sub_user (id INTEGER PRIMARY KEY);
             CREATE TABLE sub_profiles (id INTEGER PRIMARY KEY);
             CREATE TABLE relay_rules (id INTEGER PRIMARY KEY);
             CREATE TABLE relay_targets (id INTEGER PRIMARY KEY);",
        )
        .unwrap();
        migrate_to_42(&conn).unwrap();
        let channels: Vec<(String, String, String)> = {
            let mut stmt =
                conn.prepare("SELECT name, kind, config FROM notify_channels ORDER BY id").unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(channels.len(), 2, "Telegram 与 Webhook 各一");
        assert_eq!(
            channels[0],
            (
                "Telegram".into(),
                "telegram".into(),
                r#"{"chat":"42","text":"[{{site}}] {{title}}","token":"123456:AA-b_c"}"#.to_string()
            )
        );
        assert_eq!(channels[1].0, "Webhook");
        assert!(channels[1].2.contains("hooks.example"));
        // 每类事件 → 全部渠道
        let routes: Vec<(String, String)> = {
            let mut stmt = conn.prepare("SELECT event, channels FROM notify_routes ORDER BY event").unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(routes.len(), 7);
        for (event, ids) in &routes {
            assert_eq!(ids, "[1,2]", "{event} 广播到两个渠道");
        }
        // 幂等：重跑不新增
        migrate_to_42(&conn).unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM notify_channels", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn sub_usage_accumulates_crosses_and_resets_monthly() {
        let db = db();
        let id = db.create_sub_user("客户A", "t").unwrap();
        db.update_sub_user(
            id,
            &SubUser { name: "客户A".into(), enabled: true, quota_bytes: 1000, ..Default::default() },
        )
        .unwrap();
        db.bump_sub_usage(&[(id, 300, 200)]).unwrap();
        let s = db.sub_user(id).unwrap().unwrap();
        assert_eq!(s.quota_used_up + s.quota_used_down, 500);
        // 越过边沿只报一次：第三次记账已在限额外，不再算"刚越过"。
        assert_eq!(db.bump_sub_usage(&[(id, 400, 100)]).unwrap(), vec![id]);
        assert!(db.bump_sub_usage(&[(id, 10, 0)]).unwrap().is_empty());
        // 每月重置：旧的 period_start（0）落在本月之前，记账即清零重计。
        db.update_sub_user(
            id,
            &SubUser {
                name: "客户A".into(),
                enabled: true,
                quota_bytes: 1000,
                quota_reset: "monthly".into(),
                ..Default::default()
            },
        )
        .unwrap();
        db.bump_sub_usage(&[(id, 30, 0)]).unwrap();
        let s = db.sub_user(id).unwrap().unwrap();
        assert_eq!(s.quota_used_up + s.quota_used_down, 30);
        let month_start = Local::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        assert_eq!(s.quota_period_start, month_start);
        // 不存在的客户 id 让整批记账失败并回滚：调用路径（proxy_sub_of_names
        // 的映射结果）不会产生它，防御式失败好过静默丢账。
        assert!(db.bump_sub_usage(&[(9999, 1, 1)]).is_err());
    }

    /// PRAGMA settings are per connection, so a value read through any other
    /// handle proves nothing about the one the hub writes through.
    #[test]
    fn the_tuning_pragmas_reach_the_connection_the_hub_uses() {
        let db = db();
        let conn = db.conn();
        let read = |p: &str| conn.query_row(&format!("PRAGMA {p}"), [], |r| r.get::<_, i64>(0)).unwrap();
        assert_eq!(read("cache_size"), -8192, "8 MiB of page cache");
        assert_eq!(read("wal_autocheckpoint"), 256);
        assert_eq!(read("journal_size_limit"), 1_048_576);
        assert_eq!(read("busy_timeout"), 5_000);
    }

    /// A real file, since these three tests exist to exercise what happens to
    /// one. Removed by the test that created it.
    struct Scratch(String);

    impl Scratch {
        fn new() -> Self {
            Self(
                std::env::temp_dir()
                    .join(format!("monitor-test-{}.db", rand::random::<u64>()))
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", ".copy"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.0));
            }
        }
    }

    /// Backup and restore are the two operations that can lose every row in the
    /// database, so this exercises the whole path: take a copy, modify the live
    /// database, restore the copy, and confirm the change is gone.
    #[test]
    fn a_backup_restores_the_database_it_was_taken_from() {
        let scratch = Scratch::new();
        let copy = format!("{}.copy", scratch.0);
        let db = Db::open(&scratch.0).unwrap();
        let kept =
            db.create_node(&Node { name: "backed-up".into(), ..Default::default() }, "token-kept").unwrap();
        db.backup_into(&copy).unwrap();

        // Everything after the copy must disappear on restore, including a node
        // that reclaimed the deleted one's id.
        db.delete_node(kept).unwrap();
        db.create_node(&Node { name: "after".into(), ..Default::default() }, "token-after").unwrap();

        db.check_backup(&copy).unwrap();
        db.restore_from(&copy).unwrap();
        let back = db.nodes().unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!((back[0].name.as_str(), back[0].token.as_str()), ("backed-up", "token-kept"));
        assert!(db.node_by_token("token-after").unwrap().is_none(), "the row made after the copy is gone");

        // The connection remains the hub's: it can write, it is on the schema this
        // build expects, and it retains the journal mode the hub opened with --
        // the copy `VACUUM INTO` wrote is not in WAL mode.
        node(&db, 1);
        let conn = db.conn();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(),
            SCHEMA_VERSION
        );
        assert_eq!(conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0)).unwrap(), "wal");
        drop(conn);
        let _ = std::fs::remove_file(&copy);
    }

    /// The upload behind restore is an externally supplied file. Each case here
    /// is a way for it not to be a hub backup, and every one must be caught
    /// before a single page is copied over live data.
    #[test]
    fn restore_refuses_anything_that_is_not_a_backup_of_this_hub() {
        let scratch = Scratch::new();
        let db = Db::open(&scratch.0).unwrap();
        let bad = format!("{}.copy", scratch.0);
        // Each refusal carries a message the panel shows, never a bare 500.
        let refused = |why: &str| {
            let e = db.check_backup(&bad).unwrap_err();
            assert!(e.downcast_ref::<crate::Shown>().is_some(), "{why}: {e:#}");
            e.to_string()
        };

        std::fs::write(&bad, b"this is not a database at all").unwrap();
        refused("not SQLite");

        let _ = std::fs::remove_file(&bad);
        let empty = Connection::open(&bad).unwrap();
        empty.execute_batch("CREATE TABLE unrelated (a)").unwrap();
        refused("SQLite, but not this schema");

        // A file carrying its own code where a table belongs: the restore copies
        // pages, so that schema would become the one the hub runs every statement
        // against.
        empty.execute_batch(&SCHEMA.replace("PRAGMA journal_mode = WAL;", "")).unwrap();
        empty
            .execute_batch(
                "DROP TABLE session; CREATE VIEW session AS SELECT 1 AS token_hash, 2 AS expires_at",
            )
            .unwrap();
        refused("a view where a table belongs");

        // Tables with the right names and none of the right columns. Every
        // gate above passes: it is a healthy SQLite file, it carries no view or
        // trigger, every name is present, it stamps itself with this build's
        // version and uses the same page size. Restoring copies pages, so those
        // columns would become the ones the hub runs every statement against,
        // leaving the panel reporting a failed restore over a database already
        // replaced.
        let _ = std::fs::remove_file(&bad);
        let shaped = Connection::open(&bad).unwrap();
        for table in TABLES {
            shaped.execute_batch(&format!("CREATE TABLE {table} (x TEXT)")).unwrap();
        }
        shaped.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}")).unwrap();
        // Which table fails first follows the order of TABLES and is incidental;
        // naming the table and the columns is what matters.
        let missing = refused("tables without their columns");
        assert!(missing.contains("表缺少字段"), "{missing}");

        // From a hub carrying a schema this build has never seen.
        let _ = std::fs::remove_file(&bad);
        let newer = Connection::open(&bad).unwrap();
        newer.execute_batch(SCHEMA).unwrap();
        migrate_to_10(&newer).unwrap();
        newer.execute_batch(&format!("PRAGMA user_version = {}", SCHEMA_VERSION + 1)).unwrap();
        refused("from a newer hub");

        newer.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}")).unwrap();
        db.check_backup(&bad).unwrap();
    }

    /// `oldest` is what the data page compares against the retention window, so it
    /// must span both pruned tables rather than whichever happens to have rows.
    #[test]
    fn stats_report_the_earliest_history_row_and_the_window_it_is_kept_for() {
        let scratch = Scratch::new();
        let db = Db::open(&scratch.0).unwrap();
        let id = node(&db, 1);
        let now = Utc::now().timestamp();

        assert_eq!(db.stats().unwrap()["oldest"], serde_json::Value::Null, "no history, no start");
        assert_eq!(db.stats().unwrap()["retention"], 7, "an unset window is the default");

        db.insert_metric(id, now - 3 * 86_400, &serde_json::json!({"cpu": 1.0})).unwrap();
        assert_eq!(db.stats().unwrap()["oldest"], now - 3 * 86_400);

        // Older, and in the other table: the earlier of the two prevails. The probe
        // must be assigned, or the result is not this node's to file.
        let task = db
            .save_ping_task(&PingTask {
                id: 0,
                name: "p".into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes: vec![id],
                ..Default::default()
            })
            .unwrap();
        db.insert_pings(id, &[(task, now - 9 * 86_400, 12)]).unwrap();
        assert_eq!(db.stats().unwrap()["oldest"], now - 9 * 86_400);

        db.set("retention_days", "9999").unwrap();
        assert_eq!(db.stats().unwrap()["retention"], 3_650, "a stored window is still clamped");
    }

    /// Deleted rows leave free pages behind; only a rebuild returns them to the
    /// filesystem, and in WAL mode only after the checkpoint.
    #[test]
    fn vacuum_gives_the_deleted_pages_back_to_the_filesystem() {
        let scratch = Scratch::new();
        let db = Db::open(&scratch.0).unwrap();
        let id = node(&db, 1);
        let now = Utc::now().timestamp();
        let sample = serde_json::json!({"cpu": 1.0, "mem_used": 1, "swap_used": 1, "disk_used": 1,
            "net_rx": 1, "net_tx": 1, "tcp": 1, "udp": 1, "procs": 1});
        // Every row strictly before `now`: `prune(0)` cuts at its own `Utc::now()`,
        // and `ts < cutoff` would spare a row stamped in the same second the prune
        // runs.
        for i in 1..=20_000 {
            db.insert_metric(id, now - i, &sample).unwrap();
        }
        let _ = db.conn().query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        let fat = on_disk(&scratch.0);
        db.prune(0).unwrap();

        let freed = db.vacuum().unwrap();
        assert!(freed > 0, "a vacuum after deleting 20 000 rows has to return space");
        assert!(on_disk(&scratch.0) < fat);
        assert_eq!(db.stats().unwrap()["rows"]["metric"], 0);
        assert_eq!(db.nodes().unwrap().len(), 1, "vacuum keeps the rows that are left");
    }

    fn node(db: &Db, reset_day: u32) -> i64 {
        let token = format!("token-{}", rand::random::<u32>());
        db.create_node(&Node { name: "n".into(), traffic_reset_day: reset_day, ..Default::default() }, &token)
            .unwrap()
    }

    /// The country is derived from the address, so it must be dropped the moment
    /// the address no longer matches -- and only then, or every reconnect would
    /// spend an outbound request repeating a settled lookup.
    #[test]
    fn a_country_outlives_a_reconnect_and_dies_with_the_address_it_came_from() {
        let db = db();
        let id = node(&db, 1);
        let facts = serde_json::json!({"hostname": "h"});
        let save = |ip: &str| db.save_facts(id, &facts, ip, ip).unwrap();
        let stored = || db.node(id).unwrap().unwrap().country;

        assert!(save("198.51.100.4"), "a node with no country is owed a lookup");
        db.set_country(id, "US", "198.51.100.4").unwrap();
        assert!(!save("198.51.100.4"), "the same address asks nothing a second time");
        assert_eq!(stored(), "US");
        assert!(save("203.0.113.9"), "a new address is a new question");
        assert_eq!(stored(), "", "and the old answer no longer shows");
        assert!(db.country_owed(id, "203.0.113.9").unwrap(), "owed until an answer lands");
        assert!(!db.country_owed(id, "198.51.100.4").unwrap(), "nothing is owed for an address left behind");

        // A lookup issued for the old address, arriving after the move.
        db.set_country(id, "US", "198.51.100.4").unwrap();
        assert_eq!(stored(), "", "an answer about an address the node has left is dropped");
        db.set_country(id, "JP", "203.0.113.9").unwrap();
        assert_eq!(stored(), "JP", "the answer about the address it is at now lands");
        assert!(!db.country_owed(id, "203.0.113.9").unwrap());

        // The source, not the connection address, is what the country belongs to:
        // a proxy exit changing under a node with a public interface address
        // leaves the badge alone.
        assert!(!db.save_facts(id, &facts, "198.51.100.77", "203.0.113.9").unwrap());
        assert_eq!(stored(), "JP");
        // Nothing public to look up: no country, and none owed.
        assert!(!db.save_facts(id, &facts, "192.168.1.2", "").unwrap());
        assert_eq!(stored(), "");
    }

    /// A reboot: the first hello carries only the v6, the next one the v4 again.
    /// The detour spends the node's hourly lookup, so the address returned to
    /// must be answered from the row.
    #[test]
    fn a_country_returns_with_the_address_it_came_from() {
        let db = db();
        let id = node(&db, 1);
        let facts = serde_json::json!({});
        let save = |source: &str| db.save_facts(id, &facts, "198.51.100.4", source).unwrap();
        let stored = || db.node(id).unwrap().unwrap().country;
        let (v4, v6) = ("198.51.100.4", "2001:db8::5");

        save(v4);
        db.set_country(id, "RU", v4).unwrap();
        assert!(save(v6), "an address never answered is asked about");
        db.set_country(id, "US", v6).unwrap();
        assert!(!save(v4), "the address before it is not asked about again");
        assert_eq!(stored(), "RU");
        assert!(!save(v6), "nor, after that, the one in between");
        assert_eq!(stored(), "US");

        // Addresses never answered pass through without displacing the last answer.
        assert!(save("203.0.113.9"));
        assert!(save("203.0.113.10"));
        assert!(!save(v6));
        assert_eq!(stored(), "US");
    }

    /// A hub before schema 5 looked every country up from `ip`. After the
    /// upgrade a node whose source is still `ip` keeps its badge, and one whose
    /// public interface address now takes precedence is asked about again.
    #[test]
    fn countries_stored_before_the_source_column_belong_to_the_connection_address() {
        let db = db();
        let (kept, moved) = (node(&db, 1), node(&db, 1));
        let facts = serde_json::json!({});
        for id in [kept, moved] {
            db.save_facts(id, &facts, "198.51.100.4", "198.51.100.4").unwrap();
            db.set_country(id, "SG", "198.51.100.4").unwrap();
        }
        {
            let conn = db.conn();
            conn.execute_batch("ALTER TABLE node DROP COLUMN country_ip").unwrap();
            migrate(&conn, 4).unwrap();
        }
        assert!(!db.save_facts(kept, &facts, "198.51.100.4", "198.51.100.4").unwrap());
        assert_eq!(db.node(kept).unwrap().unwrap().country, "SG");
        assert!(db.save_facts(moved, &facts, "198.51.100.4", "2001:db8::5").unwrap());
        assert_eq!(db.node(moved).unwrap().unwrap().country, "");
    }

    #[test]
    fn traffic_survives_a_reboot_instead_of_resetting() {
        let db = db();
        let id = node(&db, 1);

        // The first report only establishes the baseline.
        let t = db.accumulate(id, "boot-a", (5_000, 3_000), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (0, 0));

        let t = db.accumulate(id, "boot-a", (9_000, 6_000), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (4_000, 3_000));

        // Reboot: a new boot_id with counters restarting near zero. The total must
        // not fall back to the fresh value, and the 700 bytes moved before the
        // first report are not booked, nothing having measured them.
        let t = db.accumulate(id, "boot-b", (700, 400), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (4_000, 3_000), "a reboot must not reset the total");

        // Counting resumes from the new baseline.
        let t = db.accumulate(id, "boot-b", (1_700, 900), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (5_000, 3_500));
        assert_eq!((t.month_rx, t.month_tx), (5_000, 3_500));
    }

    /// One install command pasted onto a second machine: both agents answer for
    /// the same node and evict each other, so the hub sees two boot_ids
    /// alternating, each with its own lifetime counter. Booking those would add
    /// roughly 180 GB per swap to a total that only increases.
    #[test]
    fn two_machines_sharing_one_token_cannot_inflate_the_total() {
        let db = db();
        let id = node(&db, 1);
        let (a, b) = (100_000_000_000, 80_000_000_000); // two lifetime counters

        db.accumulate(id, "boot-a", (a, a), Local::now()).unwrap();
        let t = db.accumulate(id, "boot-a", (a + 1_000, a + 1_000), Local::now()).unwrap();
        assert_eq!(t.total_rx, 1_000, "the real machine's own traffic still counts");

        // Every swap presents a boot_id with no baseline, so every swap books
        // nothing.
        for round in 0..3 {
            db.accumulate(id, "boot-b", (b + round, b + round), Local::now()).unwrap();
            db.accumulate(id, "boot-a", (a + 1_000 + round, a + 1_000 + round), Local::now()).unwrap();
        }
        let t = db.all_traffic()[&id].clone();
        assert!(t.total_rx < 10_000, "six swaps booked {} bytes, not a lifetime counter", t.total_rx);
    }

    #[test]
    fn a_shrinking_reading_re_aligns_instead_of_re_counting_history() {
        let db = db();
        let id = node(&db, 1);
        db.accumulate(id, "boot-a", (10_000, 10_000), Local::now()).unwrap();
        let t = db.accumulate(id, "boot-a", (12_000, 12_000), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (2_000, 2_000));

        // The same boot with a reduced reading: an interface included in the sum
        // has gone, so this is the remainder of the machine's history rather than
        // new bytes.
        let t = db.accumulate(id, "boot-a", (500, 500), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (2_000, 2_000));

        // Aligned to the smaller baseline, counting resumes from there.
        let t = db.accumulate(id, "boot-a", (900, 900), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (2_400, 2_400));

        // A new boot realigns identically, for the same reason: it has no baseline
        // either.
        let t = db.accumulate(id, "boot-b", (300, 300), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (2_400, 2_400));

        // One direction shrinking does not deprive the other of its increment.
        let t = db.accumulate(id, "boot-b", (100, 900), Local::now()).unwrap();
        assert_eq!((t.total_rx, t.total_tx), (2_400, 3_000));
    }

    /// The two counters that restart on their own schedules, against a total that
    /// never does. Each derives from its own stored date, so a rollover must leave
    /// the other untouched.
    #[test]
    fn day_and_month_restart_independently_while_the_total_keeps_climbing() {
        let db = db();
        let id = node(&db, 1);
        db.accumulate(id, "boot-a", (0, 0), Local::now()).unwrap();
        let t = db.accumulate(id, "boot-a", (8_000, 4_000), Local::now()).unwrap();
        assert_eq!((t.day_rx, t.day_tx), (8_000, 4_000));
        assert_eq!((t.month_rx, t.month_tx), (8_000, 4_000));

        // Midnight passes, forced through the stored date the rollover reads.
        db.conn().execute("UPDATE traffic SET day_start='1999-01-01' WHERE node_id=?1", [id]).unwrap();
        let t = db.accumulate(id, "boot-a", (9_500, 4_600), Local::now()).unwrap();
        assert_eq!((t.day_rx, t.day_tx), (1_500, 600), "a new day counts only this report's delta");
        assert_eq!(t.month_rx, 9_500, "the month is not a day");
        assert_eq!(t.total_rx, 9_500, "and the total is neither");

        // The billing period then rolls over, partway through that same day.
        db.conn().execute("UPDATE traffic SET month_start='1999-01-01' WHERE node_id=?1", [id]).unwrap();
        let t = db.accumulate(id, "boot-a", (10_000, 4_700), Local::now()).unwrap();
        assert_eq!((t.month_rx, t.month_tx), (500, 100), "a new period counts only this report's delta");
        assert_eq!((t.day_rx, t.day_tx), (2_000, 700), "the day carries on across a billing rollover");
        assert_eq!(t.total_rx, 10_000, "lifetime total is untouched by either rollover");
    }

    /// A reading is dated by its arrival, which for one held back over a boundary
    /// is earlier than its booking. It must never take the row back into a period
    /// already stamped on it, as the panel stamps the current one with a
    /// correction. A later date still moves the period, as a changed reset day
    /// requires, and a stamp later than today is not held to.
    #[test]
    fn a_reading_is_never_booked_into_a_period_already_left() {
        use chrono::TimeZone;
        let db = db();
        let id = node(&db, 20);
        let on = |d: u32| Local.with_ymd_and_hms(2026, 9, d, 12, 0, 0).unwrap();
        db.accumulate(id, "boot-a", (1_000, 0), on(24)).unwrap();
        db.accumulate(id, "boot-a", (3_000, 0), on(24)).unwrap();
        let t = db.accumulate(id, "boot-a", (3_500, 0), on(23)).unwrap();
        assert_eq!(t.day_rx, 2_500, "a reading dated the day before does not restart today");
        assert_eq!(t.month_start, "2026-09-20");

        // The reset day moves to the 1st: the period now starts earlier, and a
        // reading dated after the stamp still switches to it.
        db.update_node(id, &NodePatch { traffic_reset_day: Some(1), ..Default::default() }).unwrap();
        let t = db.accumulate(id, "boot-a", (4_000, 0), on(24)).unwrap();
        assert_eq!((t.month_start.as_str(), t.month_rx), ("2026-09-01", 500));

        // A correction stamps the current period; a reading from the one before,
        // held over the boundary, lands on top of it rather than discarding it.
        db.set_traffic(id, &TrafficPatch { month_rx: Some(10_000), ..Default::default() }).unwrap();
        let t = db.accumulate(id, "boot-a", (4_500, 0), Local::now() - chrono::Duration::days(40)).unwrap();
        assert_eq!(t.month_rx, 10_500, "the correction survives a reading dated before it");

        // A clock a year ahead stamps its own day and period. Once it is stepped
        // back, the next reading returns the row to today.
        db.accumulate(id, "boot-a", (5_000, 0), Local::now() + chrono::Duration::days(365)).unwrap();
        db.accumulate(id, "boot-a", (5_200, 0), Local::now()).unwrap();
        let t = db.all_traffic().remove(&id).unwrap();
        assert_eq!((t.day_rx, t.month_rx), (200, 200), "today reads what moved today, not zero");
    }

    /// The other half of the rollover: the counters restart on the node's next
    /// report, so a node silent since before a boundary still holds the previous
    /// period's bytes on disk. The read side must not return those.
    #[test]
    fn a_node_that_went_quiet_before_a_boundary_reads_as_zero_this_period() {
        let db = db();
        let id = node(&db, 1);
        db.accumulate(id, "boot-a", (0, 0), Local::now()).unwrap();
        db.accumulate(id, "boot-a", (8_000, 4_000), Local::now()).unwrap();
        assert_eq!(db.all_traffic()[&id].day_rx, 8_000, "still today, so it still counts");

        // Offline across both boundaries, with no report to restart either.
        db.conn()
            .execute(
                "UPDATE traffic SET day_start='1999-01-01', month_start='1999-01-01' WHERE node_id=?1",
                [id],
            )
            .unwrap();
        let t = db.all_traffic()[&id].clone();
        assert_eq!((t.day_rx, t.day_tx), (0, 0), "yesterday's bytes are not today's");
        assert_eq!((t.month_rx, t.month_tx), (0, 0), "last period's bytes are not this period's");
        assert_eq!(t.month_start, period_start(Local::now().date_naive(), 1).to_string());
        assert_eq!((t.total_rx, t.total_tx), (8_000, 4_000), "the lifetime total never resets");
    }

    /// Received 3, sent 5. "up" is the node's upload, which it sends.
    #[test]
    fn usage_is_counted_the_way_the_plan_meters_it() {
        let t = Traffic { month_rx: 3, month_tx: 5, ..Default::default() };
        assert_eq!(["sum", "up", "down", "max"].map(|mode| t.month_used(mode)), [8, 5, 3, 5]);
    }

    #[test]
    fn period_start_handles_short_months_and_wraparound() {
        let d = |y, m, day| NaiveDate::from_ymd_opt(y, m, day).unwrap();
        // Reset on the 15th, today the 20th: the current month.
        assert_eq!(period_start(d(2026, 3, 20), 15), d(2026, 3, 15));
        // The reset day itself counts as the start of the new period.
        assert_eq!(period_start(d(2026, 3, 15), 15), d(2026, 3, 15));
        // Before the reset day the period began in the previous month.
        assert_eq!(period_start(d(2026, 3, 10), 15), d(2026, 2, 15));
        // January rolls back into the previous year.
        assert_eq!(period_start(d(2026, 1, 10), 15), d(2025, 12, 15));
        // Day 31 in February clamps to the 28th; 2028 is a leap year.
        assert_eq!(period_start(d(2026, 2, 28), 31), d(2026, 2, 28));
        assert_eq!(period_start(d(2028, 2, 29), 31), d(2028, 2, 29));
    }

    #[test]
    fn deleting_a_node_takes_its_data_with_it() {
        let db = db();
        let id = node(&db, 1);
        let probe = |nodes| PingTask {
            id: 0,
            name: "cm".into(),
            target: "1.1.1.1:443".into(),
            interval: 60,
            nodes,
            ..Default::default()
        };
        let task = db.save_ping_task(&probe(vec![id])).unwrap();
        db.accumulate(id, "b", (10, 10), Local::now()).unwrap();
        db.insert_metric(id, 1, &serde_json::json!({"cpu": 1.0})).unwrap();
        db.insert_pings(id, &[(task, 1, 42)]).unwrap();
        db.delete_node(id).unwrap();
        assert!(db.node(id).unwrap().is_none());
        assert_eq!(db.metrics(id, 0, 60).unwrap().len(), 0);
        assert!(!db.all_traffic().contains_key(&id));
        // Ticked in an editor opened before the delete: named, not a 500.
        let gone = db.save_ping_task(&probe(vec![id])).unwrap_err();
        let expected = format!("节点 {id} 不存在，可能已被删除");
        assert_eq!(
            gone.downcast_ref::<crate::Shown>().map(|s| s.0.as_str()),
            Some(expected.as_str()),
            "{gone:#}"
        );

        // `ping_record` has no foreign key to cascade through, and SQLite reassigns
        // the deleted id to the next node created: without the sweep in
        // `delete_node` the new machine would draw the old one's chart.
        let fresh = node(&db, 1);
        assert_eq!(fresh, id, "the id is reused, which is what makes this reachable");
        db.save_ping_task(&PingTask { id: task, nodes: vec![fresh], ..probe(vec![]) }).unwrap();
        assert!(db.ping_records(fresh, 0, 60).unwrap().0.is_empty(), "and it starts with no history");
    }

    /// The mirror of the sweep above, on the other key of the same table. SQLite
    /// reuses a deleted probe's id as well, and the chart selects on a node's
    /// assignments, so the removed probe's samples would reappear under the new
    /// probe's name with its timeouts folded into the new loss figure.
    #[test]
    fn deleting_a_probe_takes_its_history_with_it() {
        let db = db();
        let id = node(&db, 1);
        let probe = |name: &str| PingTask {
            id: 0,
            name: name.into(),
            target: "1.1.1.1:443".into(),
            interval: 60,
            nodes: vec![id],
            ..Default::default()
        };
        let old = db.save_ping_task(&probe("tokyo")).unwrap();
        db.insert_pings(id, &[(old, 1, 999)]).unwrap();
        db.delete_ping_task(old).unwrap();

        let fresh = db.save_ping_task(&probe("singapore")).unwrap();
        assert_eq!(fresh, old, "the id is reused, which is what makes this reachable");
        assert!(db.ping_records(id, 0, 60).unwrap().0.is_empty(), "and it starts with no history");
    }

    #[test]
    fn deleting_a_proxy_node_takes_reused_port_history_with_it() {
        let db = db();
        let node = ProxyNode {
            name: "old".into(),
            protocol: "socks".into(),
            listen_port: 24000,
            server_id: 7,
            ..Default::default()
        };
        let old = db.create_proxy_node(&node, &ProxySecret::default(), "old-secret").unwrap();
        db.add_traffic_samples(&[(7, "in-24000", Utc::now().timestamp(), 123, 456)]).unwrap();
        assert_eq!(db.proxy_traffic().unwrap().len(), 1);

        db.delete_proxy_node(old).unwrap();
        let fresh = db
            .create_proxy_node(
                &ProxyNode { server_id: 1, name: "new".into(), ..node },
                &ProxySecret::default(),
                "new-secret",
            )
            .unwrap();
        assert_ne!(fresh, 0);
        assert!(
            db.proxy_traffic().unwrap().is_empty(),
            "a reused port must not inherit the deleted node's traffic"
        );
    }

    /// The overview series buckets on unix multiples of the requested size, so
    /// the same samples collapse into fewer, wider buckets instead of one point
    /// per sample (24h/1h, 7d/6h, 30d/1d on the overview page).
    #[test]
    fn the_overview_series_buckets_by_the_requested_granularity() {
        let db = db();
        // An exact 6-hour unix boundary, so every timestamp below lands in that
        // one wide bucket no matter which granularity is asked for.
        let base = 1_700_000_000 - 1_700_000_000 % (6 * 3600);
        db.add_traffic_samples(&[
            (1, "in-1", base, 100, 10),
            (1, "in-1", base + 1800, 50, 5),
            (1, "in-1", base + 4200, 7, 1),
        ])
        .unwrap();

        let hourly = db.traffic_series(base, 3600).unwrap();
        assert_eq!(hourly, vec![(base, 150, 15), (base + 3600, 7, 1)]);

        let six_hourly = db.traffic_series(base, 6 * 3600).unwrap();
        assert_eq!(six_hourly, vec![(base, 157, 16)]);
    }

    /// Counted directly from the table rather than read back through
    /// `ping_records`: that query filters on the node's assignments, so a row
    /// written under a probe it does not have is invisible to it. An assertion
    /// made through it therefore could not fail for the write this test exists to
    /// prevent.
    #[test]
    fn a_result_for_a_probe_this_node_does_not_have_is_not_stored() {
        let db = db();
        let mine = node(&db, 1);
        let other = node(&db, 1);
        let rows = || db.conn().query_row("SELECT COUNT(*) FROM ping_record", [], |r| r.get::<_, i64>(0));
        let task = db
            .save_ping_task(&PingTask {
                id: 0,
                name: "p".into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes: vec![mine],
                ..Default::default()
            })
            .unwrap();

        db.insert_pings(mine, &[(task, 1, 42)]).unwrap();
        assert_eq!(rows().unwrap(), 1, "the node the probe is assigned to files its own result");

        // A probe that exists but belongs to another node, and ids naming no probe
        // at all: what a node token can place on the wire.
        db.insert_pings(other, &[(task, 1, 42)]).unwrap();
        for invented in [7, 999_999, i64::from(i32::MAX) + 1] {
            db.insert_pings(mine, &[(invented, 1, 42)]).unwrap();
        }
        assert_eq!(rows().unwrap(), 1, "nothing else reaches the table");

        // Deleting the probe also ends its node's results, so one already in flight
        // cannot land after the sweep and be inherited by the next probe to take
        // the id.
        db.delete_ping_task(task).unwrap();
        db.insert_pings(mine, &[(task, 2, 42)]).unwrap();
        assert_eq!(rows().unwrap(), 0, "a late result for a deleted probe is dropped");
    }

    /// The strings in a `hello` come from an unvouched machine, and six of them go
    /// straight into the frame pushed to the public page every two seconds, so
    /// their length cannot be the node's to choose. `api` enforces the same bound
    /// on the one string `agent_register` accepts.
    #[test]
    fn facts_from_an_unvouched_machine_cannot_choose_their_own_length() {
        let db = db();
        let id = node(&db, 1);
        db.save_facts(id, &serde_json::json!({"os": "A".repeat(10_000), "hostname": "x\u{7}y"}), "ip", "")
            .unwrap();
        let stored = db.node(id).unwrap().unwrap();
        assert_eq!(stored.os.chars().count(), 128);
        assert_eq!(stored.hostname, "xy", "control characters break the panel's rows");
    }

    /// A correction must survive the node's return. `all_traffic` gates the month
    /// figures on the period they were written for, and `accumulate` restarts the
    /// counter when the stored period is stale, so a correction left under the
    /// previous period would read as zero and then be discarded.
    #[test]
    fn a_month_correction_is_stamped_with_the_period_it_was_made_in() {
        let db = db();
        let id = node(&db, 1);
        db.accumulate(id, "boot-a", (0, 0), Local::now()).unwrap();
        // A node silent since before its reset day still holds the old period.
        db.conn().execute("UPDATE traffic SET month_start='1999-01-01' WHERE node_id=?1", [id]).unwrap();

        db.set_traffic(
            id,
            &TrafficPatch {
                total_rx: Some(4_000),
                total_tx: Some(2_000),
                month_rx: Some(300),
                month_tx: Some(100),
            },
        )
        .unwrap();
        let t = db.all_traffic().remove(&id).unwrap();
        assert_eq!((t.month_rx, t.month_tx), (300, 100), "the correction reads back as this period's");

        let t = db.accumulate(id, "boot-a", (500, 50), Local::now()).unwrap();
        assert_eq!((t.month_rx, t.month_tx), (800, 150), "and the next report adds to it");
        assert_eq!((t.total_rx, t.total_tx), (4_500, 2_050));
    }

    #[test]
    fn partial_edits_keep_other_settings_and_live_counters() {
        let db = db();
        let id = node(&db, 1);
        let patch = |v| serde_json::from_value::<NodePatch>(v).unwrap();
        db.update_node(id, &patch(serde_json::json!({"public":false,"expires_at":"2030-01-01"}))).unwrap();
        db.update_node(id, &patch(serde_json::json!({"price":20}))).unwrap();
        let n = db.node(id).unwrap().unwrap();
        assert!(!n.public);
        assert_eq!(n.expires_at.as_deref(), Some("2030-01-01"));
        db.update_node(id, &patch(serde_json::json!({"price":0,"expires_at":null}))).unwrap();
        let n = db.node(id).unwrap().unwrap();
        assert_eq!(n.price, 0.0);
        assert_eq!(n.expires_at, None);

        db.accumulate(id, "boot", (0, 0), Local::now()).unwrap();
        db.accumulate(id, "boot", (120_000, 10_000), Local::now()).unwrap();
        db.set_traffic(id, &TrafficPatch { month_tx: Some(3_000), ..Default::default() }).unwrap();
        let t = db.all_traffic().remove(&id).unwrap();
        assert_eq!((t.total_rx, t.total_tx, t.month_rx, t.month_tx), (120_000, 10_000, 120_000, 3_000));

        db.update_node(id, &patch(serde_json::json!({"traffic_reset_day":2}))).unwrap();
        db.set_traffic(id, &TrafficPatch { month_rx: Some(7_000), ..Default::default() }).unwrap();
        let t = db.all_traffic().remove(&id).unwrap();
        assert_eq!((t.month_rx, t.month_tx), (7_000, 0));
        // Correcting only a lifetime total cannot revive the previous month's
        // bytes.
        db.conn()
            .execute("UPDATE traffic SET month_start='1999-01-01',month_tx=999 WHERE node_id=?1", [id])
            .unwrap();
        db.set_traffic(id, &TrafficPatch { total_rx: Some(130_000), ..Default::default() }).unwrap();
        assert_eq!(db.all_traffic()[&id].month_tx, 0);
    }

    #[test]
    fn a_token_is_readable_and_rotation_retires_the_old_one() {
        let db = db();
        let id = db.create_node(&Node { name: "n".into(), ..Default::default() }, "first-token").unwrap();

        // Readable, so the panel can display the install command without issuing a
        // new token.
        assert_eq!(db.node(id).unwrap().unwrap().token, "first-token");
        assert_eq!(db.node_by_token("first-token").unwrap(), Some(id));

        db.reset_token(id, "second-token").unwrap();
        assert_eq!(db.node(id).unwrap().unwrap().token, "second-token");
        assert_eq!(db.node_by_token("second-token").unwrap(), Some(id));
        assert_eq!(db.node_by_token("first-token").unwrap(), None, "the old token stops working");
    }

    #[test]
    fn nodes_can_be_reordered_atomically() {
        let db = db();
        let (a, b, c) = (node(&db, 1), node(&db, 1), node(&db, 1));
        let order = || db.nodes().unwrap().iter().map(|n| n.id).collect::<Vec<_>>();
        db.reorder_nodes(&[c, a, b]).unwrap();
        assert_eq!(order(), vec![c, a, b]);

        // Every rejected input leaves the existing order intact. The partial list
        // matters most: a stale tab would otherwise renumber around a node it never
        // saw.
        assert!(db.reorder_nodes(&[a, a, c]).is_err(), "duplicates");
        assert!(db.reorder_nodes(&[a, b]).is_err(), "a node left out");
        assert!(db.reorder_nodes(&[a, b, 9999]).is_err(), "an id that is not a node");
        assert_eq!(order(), vec![c, a, b]);
        // A node added afterwards goes to the end rather than wherever sort 0
        // places it.
        let d = node(&db, 1);
        assert_eq!(db.nodes().unwrap().iter().map(|n| n.id).collect::<Vec<_>>(), vec![c, a, b, d]);
    }

    /// Themes draw probes in the order they first appear in the rows, so the rows
    /// follow the panel's order even when a later probe alone answered in the
    /// window's first bucket.
    #[test]
    fn a_probe_chart_follows_the_panel_order() {
        let db = db();
        let id = node(&db, 1);
        let probe = |name: &str| {
            db.save_ping_task(&PingTask {
                name: name.into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes: vec![id],
                ..Default::default()
            })
            .unwrap()
        };
        let (a, b) = (probe("a"), probe("b"));
        db.reorder_ping_tasks(&[b, a]).unwrap();
        let c = probe("c");
        let listed: Vec<_> = db.ping_tasks().unwrap().iter().map(|t| t.id).collect();
        assert_eq!(listed, vec![b, a, c], "a new probe starts at the end");

        db.insert_pings(id, &[(a, 0, 10), (a, 60, 10), (b, 60, 20), (c, 60, 30)]).unwrap();
        let rows = db.ping_records(id, 0, 60).unwrap().0;
        let drawn: Vec<_> =
            rows.iter().map(|r| (r["task_id"].as_i64().unwrap(), r["ts"].as_i64().unwrap())).collect();
        assert_eq!(drawn, vec![(b, 60), (a, 0), (a, 60), (c, 60)]);
    }

    #[test]
    fn prune_drops_history_but_never_traffic_totals() {
        let db = db();
        let id = node(&db, 1);
        db.accumulate(id, "b", (100, 100), Local::now()).unwrap();
        db.accumulate(id, "b", (900, 900), Local::now()).unwrap();
        let old = Utc::now().timestamp() - 40 * 86_400;
        db.insert_metric(id, old, &serde_json::json!({"cpu": 1.0})).unwrap();
        db.insert_metric(id, Utc::now().timestamp(), &serde_json::json!({"cpu": 2.0})).unwrap();

        db.prune(30).unwrap();
        assert_eq!(db.metrics(id, 0, 60).unwrap().len(), 1);
        assert_eq!(db.all_traffic()[&id].total_rx, 800);
    }

    /// The rekeying in `open()`: rows must survive it, and the chart's query must
    /// emerge able to seek. A migration that leaves every row on the old key fails
    /// silently, and stays silent while the query it exists for scans a node's
    /// entire history.
    #[test]
    fn rekeying_ping_record_keeps_the_rows_and_lets_the_chart_query_seek() {
        let file = std::env::temp_dir().join(format!("monitor-rekey-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let path = file.to_str().unwrap();

        // A database as an older hub left it.
        let old = Connection::open(path).unwrap();
        old.execute_batch(
            "CREATE TABLE ping_record (
               node_id INTEGER NOT NULL, task_id INTEGER NOT NULL,
               ts INTEGER NOT NULL, latency INTEGER NOT NULL,
               PRIMARY KEY (node_id, task_id, ts)
             ) WITHOUT ROWID;
             INSERT INTO ping_record VALUES (1,7,100,12),(1,8,100,34),(1,7,200,56),(2,7,100,78);",
        )
        .unwrap();
        drop(old);

        let db = Db::open(path).unwrap();
        let conn = db.conn();
        let rows: Vec<(i64, i64, i64, i64)> = conn
            .prepare("SELECT node_id, task_id, ts, latency FROM ping_record ORDER BY node_id, ts, task_id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![(1, 7, 100, 12), (1, 8, 100, 34), (1, 7, 200, 56), (2, 7, 100, 78)]);

        // Without the timestamp second in the key the plan stops at `node_id=?`
        // and scans everything beneath it, and the fold in `ping_records` requires
        // rows in time order, which only the seek provides without a sorter.
        let plan: String = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {PING_ROWS}"))
            .unwrap()
            .query_map(params![1, 0, 60], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join(" | ");
        assert!(plan.contains("node_id=? AND ts>?"), "the window has to be a seek, not a scan: {plan}");
        assert!(!plan.contains("ORDER BY"), "the time order has to come off the key, not a sorter: {plan}");

        // Opening again must not rebuild a table that is already correct.
        drop(conn);
        drop(db);
        assert!(Db::open(path).is_ok());
        let _ = std::fs::remove_file(&file);
    }

    /// Every row of every table, comparable across two opens of one file.
    /// Tables a file predates -- a raw v1.0.0 file lacks the proxy tables --
    /// are skipped, so a before/after pair around a failed upgrade compares
    /// like for like.
    fn dump(conn: &Connection) -> Vec<String> {
        let mut rows = Vec::new();
        for table in TABLES {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            if exists == 0 {
                continue;
            }
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let width = stmt.column_count();
            let read =
                |r: &rusqlite::Row| (0..width).map(|i| r.get::<_, rusqlite::types::Value>(i)).collect();
            let mut found: Vec<String> = stmt
                .query_map([], |r| read(r))
                .unwrap()
                .map(|row: rusqlite::Result<Vec<_>>| format!("{table} {:?}", row.unwrap()))
                .collect();
            found.sort();
            rows.extend(found);
        }
        rows
    }

    /// A file as the oldest release left it, one row in every table.
    fn release_file(path: &str) {
        let old = Connection::open(path).unwrap();
        old.execute_batch(include_str!("testdata/schema-v1.0.0.sql")).unwrap();
        old.execute_batch(
            "INSERT INTO setting VALUES ('site', 'https://hub.example.com');
             INSERT INTO node (id, name, token, ip, country, created_at)
               VALUES (1, 'n', 't', '198.51.100.4', 'US', 1);
             INSERT INTO traffic (node_id, total_rx) VALUES (1, 5000);
             INSERT INTO metric VALUES (1, 60, 12.5, 100, 0, 0, 0, 0, 0, 0, 0);
             INSERT INTO ping_task (id, name, target) VALUES (1, 'cm', '1.1.1.1:443');
             INSERT INTO ping_node VALUES (1, 1);
             INSERT INTO ping_record VALUES (1, 1, 60, 42);
             INSERT INTO session VALUES ('h', 9999999999);
             PRAGMA user_version = 3;",
        )
        .unwrap();
    }

    /// 一个停在 fork v16 的库（metric 没有峰值列）升级到 17：上游折叠进来的
    /// net_rx_max / net_tx_max 被补上，且已有行完好。真机部署都在这条路径上。
    #[test]
    fn a_fork_v16_database_gains_the_metric_peak_columns() {
        let file = std::env::temp_dir().join(format!("monitor-v16-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let path = file.to_str().unwrap();

        // 按 fork v16 时代的形状手工搭库：metric 没有峰值列，sub_user 还是
        // v10 时的五列，user_version = 16。
        let old = Connection::open(path).unwrap();
        old.execute_batch(
            "CREATE TABLE node (id INTEGER PRIMARY KEY);
             INSERT INTO node (id) VALUES (1);
             CREATE TABLE sub_user (
               id INTEGER PRIMARY KEY,
               name TEXT NOT NULL,
               token TEXT NOT NULL UNIQUE,
               enabled INTEGER NOT NULL DEFAULT 1,
               expires_at TEXT,
               remark TEXT NOT NULL DEFAULT '',
               created_at INTEGER NOT NULL
             );
             CREATE TABLE relay_rules (
               id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL DEFAULT 0,
               name TEXT NOT NULL, listen_port TEXT NOT NULL, target TEXT NOT NULL,
               enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL
             );
             CREATE TABLE metric (
               node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
               ts INTEGER NOT NULL, cpu REAL NOT NULL,
               mem_used INTEGER NOT NULL, swap_used INTEGER NOT NULL, disk_used INTEGER NOT NULL,
               net_rx INTEGER NOT NULL, net_tx INTEGER NOT NULL,
               tcp INTEGER NOT NULL, udp INTEGER NOT NULL, procs INTEGER NOT NULL,
               PRIMARY KEY (node_id, ts)
             ) WITHOUT ROWID;
             INSERT INTO metric VALUES (1, 60, 1.0, 100, 0, 0, 500, 300, 1, 1, 1);
             PRAGMA user_version = 16;",
        )
        .unwrap();
        drop(old);

        Db::open(path).unwrap();
        let conn = Connection::open(path).unwrap();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert!(columns_of(&conn, "metric").unwrap().contains("net_rx_max"));
        assert!(columns_of(&conn, "metric").unwrap().contains("net_tx_max"));
        // 旧行的峰值回退为 0（Db::metrics 会以行均值呈现），数据本身无损。
        let (rx, rx_max): (i64, i64) = conn
            .query_row("SELECT net_rx, net_rx_max FROM metric WHERE node_id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((rx, rx_max), (500, 0));
        let _ = std::fs::remove_file(&file);
    }

    /// v1.0.0's schema, opened by this build through the startup path. Fails on
    /// a column `SCHEMA` gained without a migration or the reverse, on an index
    /// in `SCHEMA` over a column only a migration adds, and on a migration that
    /// changes the data when it runs a second time.
    #[test]
    fn an_upgraded_release_matches_a_fresh_database() {
        let scratch = Scratch::new();
        release_file(&scratch.0);
        let db = Db::open(&scratch.0).unwrap();
        let fresh = Db::open(":memory:").unwrap();
        for table in TABLES {
            assert_eq!(
                columns_of(&db.conn(), table).unwrap(),
                columns_of(&fresh.conn(), table).unwrap(),
                "{table}"
            );
        }
        let upgraded = dump(&db.conn());
        // v1.0.0 left one row in each of its 8 tables; the four proxy tables
        // the upgrade adds arrive empty, so the dump holds exactly those 8.
        assert_eq!(upgraded.len(), 8, "every row survives: {upgraded:#?}");

        // An earlier build opening the file stamps its own version, so the next
        // upgrade runs every migration again.
        db.conn().execute_batch("PRAGMA user_version = 3").unwrap();
        drop(db);
        let db = Db::open(&scratch.0).unwrap();
        assert_eq!(dump(&db.conn()), upgraded, "a second run changes nothing");
        let version: i64 = db.conn().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// 一个停在 v23 的库升级到 24：relay_rules 补齐新列，存量 target 拆行
    /// 回填为第一目标，重跑（重复迁移）不产生重复行。真机部署都在这条路径上。
    #[test]
    fn a_v23_database_gains_the_tunnel_v2_columns_and_backfilled_targets() {
        let file = std::env::temp_dir().join(format!("monitor-v23-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let path = file.to_str().unwrap();
        let old = Connection::open(path).unwrap();
        old.execute_batch(
            "CREATE TABLE relay_rules (
               id INTEGER PRIMARY KEY,
               server_id INTEGER NOT NULL DEFAULT 0,
               name TEXT NOT NULL,
               listen_port TEXT NOT NULL,
               target TEXT NOT NULL,
               enabled INTEGER NOT NULL DEFAULT 1,
               created_at INTEGER NOT NULL,
               origin_link TEXT NOT NULL DEFAULT ''
             ); -- v23 库的 server_id=0 行在 47 归一前置里指到 node 1（hub）
             INSERT INTO relay_rules (id, server_id, name, listen_port, target, enabled, created_at)
               VALUES (1, 0, '旧规则', '21580', '1.2.3.4:443', 1, 1);
             CREATE TABLE node (
               id INTEGER PRIMARY KEY,
               name TEXT NOT NULL,
               created_at INTEGER NOT NULL
             );
             INSERT INTO node (id, name, created_at) VALUES (1, 'hub机', 1);
             CREATE TABLE sub_user (
               id INTEGER PRIMARY KEY,
               name TEXT NOT NULL,
               token TEXT NOT NULL UNIQUE,
               enabled INTEGER NOT NULL DEFAULT 1,
               expires_at TEXT,
               remark TEXT NOT NULL DEFAULT '',
               created_at INTEGER NOT NULL
             );
             CREATE TABLE sub_profiles (
               id INTEGER PRIMARY KEY,
               name TEXT NOT NULL,
               token TEXT NOT NULL UNIQUE,
               template_name TEXT NOT NULL DEFAULT '',
               enabled INTEGER NOT NULL DEFAULT 1,
               created_at INTEGER NOT NULL
             );
             PRAGMA user_version = 23;",
        )
        .unwrap();
        drop(old);

        let db = Db::open(path).unwrap();
        let rules = db.relay_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].protocol, "both", "新列落默认值");
        let targets = db.relay_targets_of(1).unwrap();
        assert_eq!(targets.len(), 1, "存量 target 回填为第一目标");
        assert_eq!((targets[0].host.as_str(), targets[0].port), ("1.2.3.4", 443));
        assert_eq!(targets[0].state, "unknown");
        drop(db);

        // 再开一次（迁移重跑）：不报错、不重复回填。
        let db = Db::open(path).unwrap();
        assert_eq!(db.relay_targets_of(1).unwrap().len(), 1);
        let _ = std::fs::remove_file(&file);
    }

    /// The trigger fails the UPDATE in `migrate_to_5` after `migrate_to_4` has
    /// added its columns: a failure part-way through an upgrade.
    #[test]
    fn a_failed_upgrade_leaves_the_file_as_it_was() {
        let scratch = Scratch::new();
        release_file(&scratch.0);
        let state = |c: &Connection| {
            let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
            (version, columns_of(c, "node").unwrap(), dump(c))
        };
        let before = {
            let c = Connection::open(&scratch.0).unwrap();
            c.execute_batch(
                "CREATE TRIGGER fail BEFORE UPDATE ON node BEGIN SELECT RAISE(ABORT, 'disk full'); END",
            )
            .unwrap();
            state(&c)
        };
        assert!(Db::open(&scratch.0).is_err());
        assert_eq!(state(&Connection::open(&scratch.0).unwrap()), before, "no step of the upgrade remains");
    }

    /// Dropping `metric.load1` under a database in service. The column is
    /// `NOT NULL` with no default, so a migration that silently failed to run
    /// would not merely leave a stale column: it would prevent every history row
    /// from being written.
    #[test]
    fn dropping_load1_keeps_the_history_and_lets_new_rows_in() {
        let file = std::env::temp_dir().join(format!("monitor-load1-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let path = file.to_str().unwrap();

        // A database as a hub predating this build left it: one metric row
        // carrying a load average, stamped with the schema version of the time.
        let old = Connection::open(path).unwrap();
        old.execute_batch(
            "CREATE TABLE node (id INTEGER PRIMARY KEY, ip TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '');
             INSERT INTO node (id, ip) VALUES (1, '198.51.100.1');
             CREATE TABLE metric (
               node_id INTEGER NOT NULL, ts INTEGER NOT NULL,
               cpu REAL NOT NULL, load1 REAL NOT NULL,
               mem_used INTEGER NOT NULL, swap_used INTEGER NOT NULL, disk_used INTEGER NOT NULL,
               net_rx INTEGER NOT NULL, net_tx INTEGER NOT NULL,
               tcp INTEGER NOT NULL, udp INTEGER NOT NULL, procs INTEGER NOT NULL,
               PRIMARY KEY (node_id, ts)
             ) WITHOUT ROWID;
             INSERT INTO metric VALUES (1,60,12.5,0.75,100,0,0,0,0,0,0,0);
             PRAGMA user_version = 1;",
        )
        .unwrap();
        drop(old);

        let db = Db::open(path).unwrap();
        assert!(!schema_mentions(&db.conn(), "metric", "load1").unwrap(), "the column has to be gone");
        // The row remains, along with everything else it carried.
        let kept = &db.metrics(1, 0, 60).unwrap()[0];
        assert_eq!((kept["ts"].as_i64(), kept["cpu"].as_f64()), (Some(60), Some(12.5)));
        // The shape this build inserts now fits the table.
        db.insert_metric(1, 120, &serde_json::json!({"cpu": 2.0, "load": [0.5, 0.4, 0.3]})).unwrap();
        assert_eq!(db.metrics(1, 0, 60).unwrap().len(), 2);

        // Opening again must not attempt to drop a column already removed.
        drop(db);
        assert!(Db::open(path).is_ok());
        let _ = std::fs::remove_file(&file);
    }

    /// Removing a node from a probe must remove the probe from that node's chart.
    /// `ping_record` carries no foreign key to the assignment that produced it, so
    /// the rows outlive it until retention; the window query is what must stop
    /// drawing them, and immediately rather than at the next hourly sweep.
    #[test]
    fn a_probe_taken_off_a_node_stops_appearing_in_its_history() {
        let db = db();
        let id = node(&db, 1);
        let probe = |nodes: Vec<i64>, task| {
            db.save_ping_task(&PingTask {
                id: task,
                name: "cm".into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes,
                ..Default::default()
            })
            .unwrap()
        };
        let task = probe(vec![id], 0);
        db.insert_pings(id, &[(task, 100, 42)]).unwrap();
        assert_eq!(db.ping_records(id, 0, 60).unwrap().0.len(), 1, "an assigned probe draws");

        probe(vec![], task);
        assert!(db.ping_records(id, 0, 60).unwrap().0.is_empty(), "an unassigned one does not");

        // The rows remain: reassigning restores the history rather than starting
        // over.
        probe(vec![id], task);
        assert_eq!(db.ping_records(id, 0, 60).unwrap().0.len(), 1, "and it comes back with its history");

        // The names accompany those samples and follow the same filter: a probe
        // name is operator-supplied text that routinely carries a hostname or a
        // customer.
        assert_eq!(db.ping_task_names(id).unwrap()[&task.to_string()], "cm");
        let other = node(&db, 1);
        assert!(
            db.ping_task_names(other).unwrap().as_object().is_some_and(|m| m.is_empty()),
            "a node the probe was never assigned to must not learn its name"
        );
    }

    #[test]
    fn ping_tasks_round_trip_with_their_node_assignments() {
        let db = db();
        let (a, b) = (node(&db, 1), node(&db, 1));
        let id = db
            .save_ping_task(&PingTask {
                id: 0,
                name: "cf".into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes: vec![a, b],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(db.ping_tasks_for(a).unwrap().len(), 1);

        // Reassigning to one node must drop the other's copy.
        db.save_ping_task(&PingTask {
            id,
            name: "cf".into(),
            target: "1.1.1.1:443".into(),
            interval: 30,
            nodes: vec![a],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(db.ping_tasks_for(b).unwrap().len(), 0);
        assert_eq!(db.ping_tasks().unwrap()[0].interval, 30);
    }

    #[test]
    fn an_auto_joining_probe_is_assigned_to_nodes_created_after_it() {
        let db = db();
        let existing = node(&db, 1);
        let probe = |auto_join| PingTask {
            id: 0,
            name: "p".into(),
            target: "1.1.1.1:443".into(),
            interval: 60,
            nodes: vec![],
            auto_join,
            ..Default::default()
        };
        let joining = db.save_ping_task(&probe(true)).unwrap();
        db.save_ping_task(&probe(false)).unwrap();
        assert!(db.ping_tasks_for(existing).unwrap().is_empty(), "existing nodes follow the list alone");

        let added = node(&db, 1);
        let assigned: Vec<i64> =
            db.ping_tasks_for(added).unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
        assert_eq!(assigned, [joining]);
        assert!(db.ping_tasks().unwrap()[0].auto_join);

        // A new node takes every auto-joining probe at once, so their count is
        // held to what one agent runs.
        for _ in 1..Db::MAX_PROBES_PER_NODE {
            db.save_ping_task(&probe(true)).unwrap();
        }
        assert!(db.save_ping_task(&probe(true)).is_err());
        assert_eq!(db.ping_tasks().unwrap().len() as i64, Db::MAX_PROBES_PER_NODE + 1);
    }

    /// The editor's list is a snapshot, while `create_node` assigns auto-joining
    /// probes whenever a node registers.
    #[test]
    fn an_edit_applies_only_the_assignments_it_changed() {
        let db = db();
        let (a, b) = (node(&db, 1), node(&db, 1));
        let save = |id, nodes: Vec<i64>, base: Vec<i64>| {
            db.save_ping_task(&PingTask {
                id,
                name: "p".into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes,
                auto_join: true,
                base: Some(base),
            })
        };
        let assigned = |id| {
            let mut nodes = db.ping_tasks().unwrap().into_iter().find(|t| t.id == id).unwrap().nodes;
            nodes.sort_unstable();
            nodes
        };
        let id = save(0, vec![a], vec![]).unwrap();
        let joined = node(&db, 1);

        // Opened before `joined` existed, so it is in neither list and stays.
        save(id, vec![a, b], vec![a]).unwrap();
        assert_eq!(assigned(id), [a, b, joined]);
        save(id, vec![b], vec![a, b]).unwrap();
        assert_eq!(assigned(id), [b, joined]);

        // Ticked after joining on its own: already assigned, not an error.
        save(id, vec![b, joined], vec![b]).unwrap();
        assert_eq!(assigned(id), [b, joined]);
        // OR IGNORE leaves the foreign key in force.
        assert!(save(id, vec![b, joined, 9999], vec![b, joined]).is_err(), "an id that is not a node");
        assert_eq!(assigned(id), [b, joined]);

        // A node deleted since the editor opened is in both lists and untouched.
        db.delete_node(b).unwrap();
        save(id, vec![b, joined], vec![b, joined]).unwrap();

        db.delete_ping_task(id).unwrap();
        assert!(save(id, vec![], vec![]).is_err(), "a deleted probe is not reported as saved");
        assert!(db.ping_tasks().unwrap().is_empty());
    }

    /// The agent caps the probe list it will run and drops the remainder with
    /// nothing but a line in its own journal. The hub knows the total, so the hub
    /// issues the refusal; otherwise the panel lists probes that never ran and
    /// charts that stay empty, with the only record on the node.
    #[test]
    fn a_node_cannot_be_given_more_probes_than_the_agent_will_run() {
        let db = db();
        let id = node(&db, 1);
        let save = |task: i64, nodes: Vec<i64>| {
            db.save_ping_task(&PingTask {
                id: task,
                name: "p".into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes,
                ..Default::default()
            })
        };
        for _ in 0..Db::MAX_PROBES_PER_NODE {
            save(0, vec![id]).unwrap();
        }
        assert_eq!(db.ping_tasks_for(id).unwrap().len() as i64, Db::MAX_PROBES_PER_NODE);

        let refused = save(0, vec![id]).expect_err("one past the cap must be refused");
        assert!(refused.to_string().contains("探测任务"), "{refused}");
        // Rolled back entirely: the probe must not survive its assignment being
        // rejected, or the panel accumulates one that never runs.
        assert_eq!(db.ping_tasks().unwrap().len() as i64, Db::MAX_PROBES_PER_NODE);
        assert_eq!(db.ping_tasks_for(id).unwrap().len() as i64, Db::MAX_PROBES_PER_NODE);

        // Editing an existing probe does not count as adding one.
        let first = db.ping_tasks().unwrap()[0].id;
        save(first, vec![id]).expect("an existing probe can still be edited at the cap");
    }

    /// 限速字段走真实落库闭环：create/update 的 SQL 是显式列名，漏列会静默
    /// 丢值（教训同 static_content 事件），所以单测必须读回验证。
    #[test]
    fn node_rates_round_trip_through_the_database() {
        let db = db();
        let node = ProxyNode {
            name: "jp".into(),
            protocol: "vless-reality".into(),
            listen_port: 24002,
            server_id: 3,
            rate_up: 20,
            rate_down: 50,
            ..Default::default()
        };
        let id = db.create_proxy_node(&node, &ProxySecret::default(), "secret").unwrap();
        let got = db.proxy_node(id).unwrap().unwrap();
        assert_eq!((got.rate_up, got.rate_down), (20, 50));
        let cleared = ProxyNode { server_id: 1, rate_up: 0, rate_down: 0, ..got.clone() };
        db.update_proxy_node(&cleared, None, None).unwrap();
        let got = db.proxy_node(id).unwrap().unwrap();
        assert_eq!((got.rate_up, got.rate_down), (0, 0));
    }

    /// 改端口（或挪服务器）必须带着历史走：采样与连接日志以
    /// server_id + in-{端口} 为键，不改写就会以「节点可能已删除」残留，
    /// 日志页的节点筛选也随之失配。
    #[test]
    fn editing_a_nodes_port_takes_its_history_along() {
        let db = db();
        let node = ProxyNode {
            name: "hk".into(),
            protocol: "socks".into(),
            listen_port: 24001,
            server_id: 3,
            ..Default::default()
        };
        let id = db.create_proxy_node(&node, &ProxySecret::default(), "secret").unwrap();
        let ts = Utc::now().timestamp();
        db.add_traffic_samples(&[(3, "in-24001", ts, 100, 10)]).unwrap();
        db.upsert_connection_logs(
            3,
            &[ConnectionLogRow {
                conn_id: "c1".into(),
                user: "alice".into(),
                inbound: "in-24001".into(),
                network: "tcp".into(),
                source: "1.2.3.4:5".into(),
                host: "example.com".into(),
                port: 443,
                first: ts,
                last: ts,
                up: 1,
                down: 2,
            }],
        )
        .unwrap();

        let moved = ProxyNode { id, listen_port: 24002, ..node };
        db.update_proxy_node(&moved, None, None).unwrap();

        let traffic = db.proxy_traffic().unwrap();
        assert!(
            traffic.iter().any(|(sid, tag, _, _, tr, _)| *sid == 3 && tag == "in-24002" && *tr == 100),
            "samples follow the node to its new port: {traffic:?}"
        );
        assert!(!traffic.iter().any(|(_, tag, ..)| tag == "in-24001"), "the old tag must not linger");
        let (rows, total) = db
            .connection_logs(&ConnLogFilter {
                server_id: Some(3),
                user: None,
                node: Some("in-24002".into()),
                q: None,
                since: None,
                until: None,
                page: 1,
            })
            .unwrap();
        assert_eq!(total, 1, "the log row answers to the node's new tag");
        assert_eq!(rows[0]["inbound"], "in-24002");
        assert_eq!(db.proxy_node(id).unwrap().unwrap().listen_port, 24002);
    }

    /// 压缩把 8 天前的零散采样并成整点小时行：总量（proxy_traffic 的
    /// total 列）一个字节都不能变，新采样原样保留，二次运行不再改写
    /// （幂等）。
    #[test]
    fn compaction_folds_old_samples_into_hour_rows_without_losing_a_byte() {
        let db = db();
        let base = 1_700_000_000 - 1_700_000_000 % 3600; // an exact unix hour
        let old = base - 9 * 86_400;
        let fresh = Utc::now().timestamp() - 60; // well inside the raw window
        db.add_traffic_samples(&[
            (1, "in-1", old + 7, 100, 10),
            (1, "in-1", old + 1800, 50, 5),
            (1, "in-2", old + 3600 + 42, 7, 1), // the next hour, another node
            (1, "in-1", fresh, 500, 50),        // stays raw
            (1, "in-1", base, 3, 4),            // hour-aligned raw row: left as is
        ])
        .unwrap();
        let total_before: (i64, i64) =
            db.proxy_traffic().unwrap().iter().fold((0, 0), |a, t| (a.0 + t.4, a.1 + t.5));

        let removed = db.compact_traffic_samples(8).unwrap();
        assert_eq!(removed, 3, "the three misaligned old rows are rewritten");

        let total_after: (i64, i64) =
            db.proxy_traffic().unwrap().iter().fold((0, 0), |a, t| (a.0 + t.4, a.1 + t.5));
        assert_eq!(total_after, total_before, "compaction must not move a byte");

        let old_hour_rows: Vec<_> = db.traffic_series(old - 3600, 3600).unwrap().into_iter().collect();
        assert!(
            old_hour_rows.contains(&(base - 9 * 86_400, 150, 15)),
            "two samples folded into one hour row"
        );
        assert!(old_hour_rows.contains(&(base - 9 * 86_400 + 3600, 7, 1)), "the next hour stays its own row");

        // 幂等：小时行整点对齐，二次运行无事可做。
        assert_eq!(db.compact_traffic_samples(8).unwrap(), 0);
        let total_again: (i64, i64) =
            db.proxy_traffic().unwrap().iter().fold((0, 0), |a, t| (a.0 + t.4, a.1 + t.5));
        assert_eq!(total_again, total_before);

        // 新采样未被触碰。
        let fresh_rows = db.traffic_series(fresh - 3600, 3600).unwrap();
        assert!(fresh_rows.iter().any(|(_, rx, tx)| *rx == 500 && *tx == 50));
    }

    /// 客户小时汇总（迁移 23）：建表时从 connection_log 回填一次，此后记账
    /// 事务同步增量；排行按窗口取数，清理按保留期删桶。
    #[test]
    fn sub_usage_hourly_feeds_the_windowed_customer_rank() {
        let db = db();
        let sub = db.create_sub_user("客户A", "tok").unwrap();
        let node = ProxyNode {
            name: "hk".into(),
            protocol: "socks".into(),
            listen_port: 24010,
            server_id: 2,
            ..Default::default()
        };
        let node_id = db.create_proxy_node(&node, &ProxySecret::default(), "secret").unwrap();
        let pu = db.create_proxy_user(node_id, "alice", "cred").unwrap();
        db.set_proxy_user_sub(pu, Some(sub)).unwrap();

        // 日志落库时表已存在但为空（建表回填发生在开库时）——重跑迁移的
        // 回填 SQL（幂等，OR IGNORE）把已有日志折算成历史。
        let now = Utc::now().timestamp();
        db.upsert_connection_logs(
            2,
            &[ConnectionLogRow {
                conn_id: "c1".into(),
                user: "alice".into(),
                inbound: "in-24010".into(),
                network: "tcp".into(),
                source: "9.9.9.9:1".into(),
                host: "example.com".into(),
                port: 443,
                first: now - 30,
                last: now - 20,
                up: 111,
                down: 222,
            }],
        )
        .unwrap();
        assert!(db.sub_usage_rank(now - 3600).unwrap().is_empty());
        migrate_to_23(&db.conn()).unwrap();
        assert_eq!(db.sub_usage_rank(now - 3600).unwrap(), vec![(sub, 111, 222)]);

        // 记账增量进同一小时的桶：两笔并成一行。
        db.bump_sub_usage(&[(sub, 100, 200)]).unwrap();
        db.bump_sub_usage(&[(sub, 10, 20)]).unwrap();
        assert_eq!(db.sub_usage_rank(now - 3600).unwrap(), vec![(sub, 221, 442)]);
        assert!(db.sub_usage_rank(now + 3600).unwrap().is_empty(), "窗口起点之后才有的桶不计入");

        // 清理按保留期删桶：保留 0 天即全删。
        db.prune_sub_usage_hourly(0).unwrap();
        assert!(db.sub_usage_rank(now - 3600).unwrap().is_empty());
    }

    /// agent_jobs 审计清理：窗口外的推送记录删掉，新近的保留。
    /// （风暴期该表一天 1400 行，没有清理就只增不减。）
    #[test]
    fn agent_jobs_prune_drops_only_rows_beyond_the_window() {
        let db = db();
        db.add_agent_job(1, "proxy.apply_config", "fresh").unwrap();
        db.conn()
            .execute(
                "INSERT INTO agent_jobs (server_id, method, state, detail, created_at)
                 VALUES (1, 'relay.apply', 'pushed', 'storm-era', ?1)",
                [Utc::now().timestamp() - 31 * 86_400],
            )
            .unwrap();
        assert_eq!(db.prune_agent_jobs(30).unwrap(), 1, "只删 30 天外的那行");
        let rest: i64 = db.conn().query_row("SELECT COUNT(*) FROM agent_jobs", [], |r| r.get(0)).unwrap();
        assert_eq!(rest, 1);
    }

    /// 客户端汇总按 IP 归组：同一客户端的每次连接源端口不同，次数必须累计
    /// 而不是按 IP:端口 拆成多行；v6 来源按方括号截断。
    #[test]
    fn the_client_summary_accross_ports_counts_one_ip_as_one_client() {
        let db = db();
        let now = Utc::now().timestamp();
        let row = |conn_id: &str, port: u16| ConnectionLogRow {
            conn_id: conn_id.into(),
            user: String::new(),
            inbound: String::new(),
            network: "tcp".into(),
            source: format!("203.0.113.7:{port}"),
            host: "example.com".into(),
            port: 443,
            first: now,
            last: now,
            up: 1,
            down: 2,
        };
        db.upsert_connection_logs(1, &[row("a", 5000), row("b", 5001), row("c", 5002)]).unwrap();
        let (hosts, clients) = db
            .connection_log_summary(&ConnLogFilter {
                server_id: Some(1),
                user: None,
                node: None,
                q: None,
                since: None,
                until: None,
                page: 1,
            })
            .unwrap();
        assert_eq!(hosts[0]["count"], 3, "the host card still counts every connection");
        assert_eq!(clients.len(), 1, "three connections from one IP = one client");
        assert_eq!(clients[0]["source"], "203.0.113.7");
        assert_eq!(clients[0]["count"], 3);
    }
}
