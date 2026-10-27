//! IP 归属地（ip2region xdb 离线库，IPv4）。
//!
//! xdb 文件放在数据库同目录、名 `ip2region.xdb`（服务器部署位置即
//! /opt/monitor/data/ip2region.xdb；不入仓库，下载 ip2region 仓库的
//! data/ip2region_v4.xdb 即可，v3 格式 ~11MB）。文件缺失或损坏时整个
//! 功能静默关闭：lookup 返回空串，前端退化为只显示 IP。
//!
//! 文件全量驻留内存，查询为纯内存二分。格式（v3 头，与官方 maker/rust
//! 对齐）：头 256 字节，偏移 16 的 u16(LE) 是 ip_version（4=IPv4）；
//! 向量索引 256×256×8 字节紧随其后，单元 = (首字节×256+次字节)，项为
//! 段索引起止指针 u32(LE)；段索引每条 14 字节 = sip(4) + eip(4) +
//! 数据长度 u16(LE) + 数据指针 u32(LE)，**v4 的 IP 按小端字节存储**；
//! 数据区为 UTF-8 的 "国家|区域|省份|城市|ISP"。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::OnceLock;

const HEADER_LEN: usize = 256;
const VECTOR_LEN: usize = 256 * 256 * 8;
/// v4 段索引条目：sip(4) + eip(4) + 长度(2) + 指针(4)。
const SEGMENT_LEN: usize = 14;
const XDB_NAME: &str = "ip2region.xdb";

static XDB: OnceLock<Option<Xdb>> = OnceLock::new();

struct Xdb {
    buf: Vec<u8>,
}

impl Xdb {
    fn open(path: &Path) -> Option<Self> {
        let buf = std::fs::read(path).ok()?;
        if buf.len() < HEADER_LEN + VECTOR_LEN {
            return None;
        }
        // 只接 v4 库；连接日志里的 v6 来源本就不解析。
        if u16::from_le_bytes([buf[16], buf[17]]) != 4 {
            return None;
        }
        Some(Self { buf })
    }

    /// 命中返回 region 原始串，未命中/文件损坏返回 None。
    fn search(&self, ip: Ipv4Addr) -> Option<&str> {
        let octets = ip.octets();
        let v = HEADER_LEN + (usize::from(octets[0]) * 256 + usize::from(octets[1])) * 8;
        // 向量项两个指针都是 LE；0 表示该网段无数据。
        let cell = self.buf.get(v..v + 8)?;
        let start = u32::from_le_bytes(cell[0..4].try_into().ok()?) as usize;
        let end = u32::from_le_bytes(cell[4..8].try_into().ok()?) as usize;
        if start == 0 || start > end || end + SEGMENT_LEN > self.buf.len() {
            return None;
        }

        // 段索引的 IP 是小端字节：反转回网络序再按字节比较。
        let ip_bytes = octets;
        let le = |b: &[u8]| -> Option<[u8; 4]> {
            let mut a: [u8; 4] = b.try_into().ok()?;
            a.reverse();
            Some(a)
        };
        let mut left = 0usize;
        let mut right = (end - start) / SEGMENT_LEN;
        while left <= right {
            let mid = (left + right) / 2;
            let off = start + mid * SEGMENT_LEN;
            let entry = self.buf.get(off..off + SEGMENT_LEN)?;
            let sip = le(&entry[0..4])?;
            let eip = le(&entry[4..8])?;
            if ip_bytes < sip {
                right = mid.checked_sub(1)?;
            } else if ip_bytes > eip {
                left = mid + 1;
            } else {
                let len = u16::from_le_bytes([entry[8], entry[9]]) as usize;
                let ptr = u32::from_le_bytes(entry[10..14].try_into().ok()?) as usize;
                let data = self.buf.get(ptr..ptr.checked_add(len)?)?;
                return std::str::from_utf8(data).ok();
            }
        }
        None
    }
}

/// 启动时按数据库路径初始化（同目录 XDB_NAME）。进程内生效一次，重复
/// 调用无副作用；失败（无文件/坏文件）保持关闭态，不重试。
pub fn init(db_path: &str) {
    let dir = Path::new(db_path).parent().unwrap_or_else(|| Path::new("."));
    let _ = XDB.set(Xdb::open(&dir.join(XDB_NAME)));
}

/// "1.2.3.4:5678" / "[::1]:443" / "1.2.3.4" → "中国·广东省·深圳市·电信"
/// 这样的短标签；无库 / 非 IPv4（v6 不解析，IPv4-mapped 除外） / 未命中 → ""。
pub fn lookup(source: &str) -> String {
    let Some(xdb) = XDB.get().and_then(|o| o.as_ref()) else {
        return String::new();
    };
    let v4 = match parse_client_ip(source) {
        Some(IpAddr::V4(v4)) => v4,
        _ => return String::new(),
    };
    format_region(xdb.search(v4).unwrap_or_default())
}

/// 从 "ip:port" / "[v6]:port" / 裸 IP 提取地址；IPv4-mapped 折回 v4。
fn parse_client_ip(source: &str) -> Option<IpAddr> {
    let ip = source.parse::<SocketAddr>().ok().map(|a| a.ip()).or_else(|| source.parse::<IpAddr>().ok())?;
    Some(match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    })
}

/// "国家|0|广东省|深圳市|电信" → "中国·广东省·深圳市·电信"；0/空段丢弃；
/// 连续重复段折叠（保留地址 "Reserved×3"、直辖市「北京市·北京市」等）。
fn format_region(region: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for s in region.split('|').filter(|s| !s.is_empty() && *s != "0") {
        if parts.last() != Some(&s) {
            parts.push(s);
        }
    }
    parts.join("·")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工拼一个最小 v4 xdb：头 + 向量 + 一条段索引 + 一条数据，覆盖
    /// 1.0.0.0–1.0.0.255。1.0.1.0 起该向量单元无段、8.x 单元无指针。
    fn mini_xdb() -> Xdb {
        let region = "中国|0|广东省|深圳市|电信";
        let seg = (HEADER_LEN + VECTOR_LEN) as u32;
        let data_ptr = seg + SEGMENT_LEN as u32;
        let seg_off = seg as usize;
        // 布局：[头 256 | 向量 512K | 段索引 14B | region 数据]。
        let mut buf = vec![0u8; seg_off + SEGMENT_LEN + region.len()];
        buf[16..18].copy_from_slice(&4u16.to_le_bytes());
        // u32::from(Ipv4Addr) 是网络序数值，to_le_bytes 即文件要求的小端存储。
        buf[seg_off..seg_off + 4].copy_from_slice(&u32::from(Ipv4Addr::new(1, 0, 0, 0)).to_le_bytes());
        buf[seg_off + 4..seg_off + 8].copy_from_slice(&u32::from(Ipv4Addr::new(1, 0, 0, 255)).to_le_bytes());
        buf[seg_off + 8..seg_off + 10].copy_from_slice(&(region.len() as u16).to_le_bytes());
        buf[seg_off + 10..seg_off + 14].copy_from_slice(&data_ptr.to_le_bytes());
        buf[seg_off + SEGMENT_LEN..].copy_from_slice(region.as_bytes());
        let cell = HEADER_LEN + 256 * 8; // 1.0.x.x → 向量单元 (1, 0)
        buf[cell..cell + 4].copy_from_slice(&seg.to_le_bytes());
        buf[cell + 4..cell + 8].copy_from_slice(&seg.to_le_bytes());
        Xdb { buf }
    }

    #[test]
    fn a_v4_ip_resolves_through_port_and_mapped_v6_forms() {
        let xdb = mini_xdb();
        assert_eq!(xdb.search(Ipv4Addr::new(1, 0, 0, 128)), Some("中国|0|广东省|深圳市|电信"));
        assert_eq!(xdb.search(Ipv4Addr::new(1, 0, 1, 1)), None, "one past the segment end");
        assert_eq!(xdb.search(Ipv4Addr::new(8, 8, 8, 8)), None, "vector cell with no pointers");
    }

    #[test]
    fn lookup_formats_the_region_and_ignores_port_and_v6() {
        let xdb = mini_xdb();
        assert_eq!(format_region(xdb.search(Ipv4Addr::new(1, 0, 0, 7)).unwrap()), "中国·广东省·深圳市·电信");
        assert_eq!(format_region("美国|0|0|0|0"), "美国");
        assert_eq!(format_region("0|0|0|0|0"), "");
        assert_eq!(format_region("Reserved|Reserved|Reserved"), "Reserved");
        assert_eq!(format_region("中国|0|北京市|北京市|CN"), "中国·北京市·CN");
        let parsed = |s: &str| parse_client_ip(s).map(|i| i.to_string());
        assert_eq!(parsed("1.2.3.4:5678").as_deref(), Some("1.2.3.4"));
        assert_eq!(parsed("1.2.3.4").as_deref(), Some("1.2.3.4"));
        assert_eq!(parsed("[::ffff:1.2.3.4]:443").as_deref(), Some("1.2.3.4"), "IPv4-mapped folds back");
        assert_eq!(parsed("[2001:db8::1]:443").as_deref(), Some("2001:db8::1"), "plain v6 stays itself");
        assert_eq!(parsed("not-an-ip"), None);
    }
}
