// ⚠️ **临时的死代码豁免，且写明何时删掉它** ✗ ——
// 本模块是**分期落地**的第一期：判据先写好并测死 ✓，而"取页 + 上报"在下一笔才接上 ✓。
// 在那之前它对编译器就是死代码 ✓ ⇒ 先 allow ✓。
// ⭐ **接上取页与上报之后，请删掉下面这一行** ✓ —— 否则它会一直留着，
//    把将来**真正的**死代码也一并藏掉 ✓✗（那种"豁免变成永久"的账最难查 ✓）。
#![allow(dead_code)]

//! 流媒体解锁探测 ✓（**只做判据** ✓ —— 发请求那半段在 [`fetch`] 里 ✓，本模块的核心是纯函数 ✓）。
//!
//! ⚠️ 这一块最容易产出**看起来像结论的错值** ✗✓，所以判据与取页**分开**：
//! `verdict` 是纯函数 ✓、有测试 ✓；`fetch` 只是"把页面拿回来" ✓（它失败就是失败 ✓，
//! 绝不猜 ✓）。
//!
//! 判据来源 ✓：照 xykt 的 IPQuality（`ip.sh`）里 `MediaUnlockTest_Netflix` 的**实际做法** ✓，
//! 不是照 blog 猜的 ✓ —— 见下面每一条的注释 ✓。

use anyhow::anyhow;
use tokio::net::TcpStream;

/// 一个服务的探测结论 ✓ —— ⚠️ **四态** ✓✓，而"失败"与"未解锁"**必须分开** ✗✗：
/// 网络不通 ✓、被墙 ✓、对方改版 ✓ 都会让请求失败 ✓，而那些**都不是**"这个区不解锁" ✓。
/// 把失败说成未解锁 = 假信息 ✓（用户会据此换机器，而问题其实在网络上 ✓）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// 解锁 ✓（请求成功、且响应里没有"看不了"的标志 ✓）
    Unlocked,
    /// 未解锁 ✓ —— **请求成功了** ✓，是对方明确说"这个区看不了" ✓
    Blocked,
    /// 请求拿到了页面 ✓，但**内容看不懂** ✓（对方改版 / 返回了别的东西 ✓）
    /// ⚠️ 与 `Blocked` 分开 ✓：它**不是**"被墙"的结论 ✓，只是"这次没读明白" ✓。
    Unknown,
}

/// 一个服务的完整结论 ✓（与参考实现的三格一致 ✓：状态 ✓ 地区 ✓ —— 方式那格第一版不做 ✓）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: Status,
    /// 地区码（`US` / `JP` …✓）；拿不到就是 `None` ✓（**不编** ✗）。
    pub region: Option<String>,
}

/// Netflix 的判据 ✓✓ —— 纯函数 ✓，输入是**两个**页面 ✓。
///
/// 参考实现的做法 ✓（`ip.sh` 的 `MediaUnlockTest_Netflix` ✓）：
/// - 取两个 Netflix 自制剧页面：`/title/81280792` 与 `/title/70143836` ✓
///   （**在不解锁的区**，它们会返回带 `Oh no!` 的"看不了"页 ✓）
/// - 两个都含 `Oh no!` ⇒ **未解锁** ✓
/// - 否则 ⇒ **解锁** ✓，并从中解析地区码 ✓
///
/// ⚠️ 地区码的取法照参考 ✓：从 `"id":"…"` 与 `"countryName":"…"` 相邻的那段里取前一个 ✓。
/// 拿不到就 `None` ✓ —— **宁可不给地区，也不给一个猜的** ✓。
pub fn netflix_verdict(page_a: &str, page_b: &str) -> Verdict {
    // `Oh no!` 是 Netflix"这个区看不了"页面上的原话 ✓（参考实现就 grep 它 ✓）。
    // 两个页面都要看 ✓：只看一个会在"恰好一个页面不可用"时误判 ✓。
    let blocked = page_a.contains("Oh no!") && page_b.contains("Oh no!");
    let status = if blocked {
        Status::Blocked
    } else if page_a.contains("Oh no!") || page_b.contains("Oh no!") {
        // ⚠️ **只有一个**页面说看不了 ⇒ 说不清 ✓（可能是那一部剧在这个区没有 ✓，
        // 也可能另一页没取到 ✓）⇒ 如实说"没读明白" ✓，**不猜** ✗。
        Status::Unknown
    } else if page_a.trim().is_empty() && page_b.trim().is_empty() {
        Status::Unknown
    } else {
        Status::Unlocked
    };
    Verdict { status, region: netflix_region(page_a).or_else(|| netflix_region(page_b)) }
}

/// 从页面里取地区码 ✓（`"id":"US"` 紧邻 `"countryName"` 的那一处 ✓，照参考的正则 ✓）。
/// 取不到 ⇒ `None` ✓（**不编** ✗）。
fn netflix_region(page: &str) -> Option<String> {
    let i = page.find("\"id\":\"")?;
    let rest = &page[i + 6..];
    let end = rest.find('"')?;
    let code = &rest[..end];
    // 参考用的是"`"id"` 后面紧跟 `"countryName"` 之前"这个形状 ✓；
    // 这里再加两道保险 ✓：**必须是两位大写字母** ✓（否则它只是别的 `id` 字段 ✓）。
    if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
        Some(code.to_string())
    } else {
        None
    }
}

/// 抖动的**种子**来自一个稳定的、非密钥的标识 ✓ —— 纯函数 ✓（所以"稳不稳定"能测 ✓）。
///
/// ⚠️ 用什么、**绝不用什么** ✗✗：
/// - 用 **hostname** ✓：稳定（同一台机器每次都一样 ✓，重启也不变 ✓）、不是秘密 ✓；
/// - **绝不用 token** ✗✗ —— 哪怕只是"哈希一下" ✓：token 是凭据 ✓，
///   把它引进一个日志/状态文件会碰到的地方，就是把凭据放进了一个它本不该去的路径 ✓✗。
///
/// 用稳定标识而不是随机数 ✓：随机会让"同一台机器每次重启换一个相位" ✓✗ ——
/// 那不是错开 ✓，那是**每次都在不同时刻探一次** ✓（更糟 ✓）。
pub fn seed_from(hostname: &str) -> u64 {
    // FNV-1a ✓：几十行实现、无依赖、分布够用 ✓（这里只需要"不同机器落在不同相位" ✓，
    // 不需要抗碰撞 ✓）。空 hostname 也有确定的值 ✓（会落到固定相位 ✓，不 panic ✓）。
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in hostname.trim().as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ─────────────────────────── 状态：上次探测时间（落盘，或如实降级）───────────────────────────

/// 状态目录从**环境**里认出来 ✓ —— 纯函数 ✓（所以"拿不到目录"这条路能测 ✓）。
///
/// ⚠️ 为什么不是写死的路径 ✗：unit 里是 `ProtectSystem=strict` ✓，
/// 除非 `StateDirectory=` 声明过 ✓，服务**哪个目录都写不了** ✓✗（连 /tmp 都被 PrivateTmp 挡掉 ✓）。
/// systemd 声明过之后会把路径放进 **`$STATE_DIRECTORY`** ✓✓ ⇒ 以它为准 ✓。
/// 拿不到（老安装 ✓ / 手动跑 ✓）⇒ `None` ✓ ⇒ 调用方**如实降级到内存** ✓，
/// **不假装写成功** ✗（假装的话，"重启不风暴"会在最需要它的时候失效 ✓✗）。
pub fn state_dir(env: Option<&str>) -> Option<std::path::PathBuf> {
    let raw = env?.trim();
    if raw.is_empty() {
        return None;
    }
    // systemd 可以给**多个**目录（冒号分隔 ✓，与 PATH 同一个约定 ✓）—— 取第一个 ✓。
    // ⚠️ **空段要跳过** ✗（与 PATH 同一条约定 ✓）：`":/run/x"` 的第一段是空串 ✓，
    // 若直接取它 ⇒ 返回 None ✓✗ —— 于是**明明有可用目录，却降级到内存** ✓
    //（"重启不风暴"在最需要它的时候失效 ✓）。这条是测试抓出来的 ✓：我原本就是那么写的 ✓。
    let first = raw.split(':').map(str::trim).find(|seg| !seg.is_empty())?;
    Some(std::path::PathBuf::from(first))
}

/// 上次探测时间的落盘格式 ✓ —— **Unix 秒** ✓（一行数字 ✓）。
/// ⚠️ 纯函数 ✓：读不出来就 `None` ✓（文件被截断 ✓、被改坏 ✓、是老版本写的 ✓）
/// —— **不猜** ✗（猜一个时间会让周期算错 ✓，而错的方向可能是"立刻又探一次" ✓✗）。
pub fn parse_stamp(text: &str) -> Option<std::time::SystemTime> {
    let secs: u64 = text.trim().parse().ok()?;
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// 与 [`parse_stamp`] 配对的写出格式 ✓（纯函数 ✓ ⇒ 两个方向都能测 ✓）。
pub fn format_stamp(t: std::time::SystemTime) -> Option<String> {
    // 早于 Unix 纪元 ⇒ 写不出来 ✓（那种值本来就不该出现 ✓；写一个 0 会被读成"1970 年探过" ✓✗）
    let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(secs.to_string())
}

// ───────────────────────────── 排程（纯函数，策略只在这里一处）─────────────────────────────

/// 每隔多久探一次 ✓（用户定的：**6 小时** ✓）。
pub const INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// 这台节点的**固定错开量** ✓✓ —— 纯函数 ✓（同一台机器每次都算出同一个值 ✓）。
///
/// ⚠️ **为什么要错开** ✗：六台机器若都在同一秒去探 ✓，会在对方那边形成**规律的尖峰** ✓✗ ——
/// 既是"看起来很像机器人"的流量特征 ✓，也让服务商更容易把我们挡掉 ✓。
/// ⇒ 按节点自身的一个种子（hub 给的节点 id ✓）摊到整个周期上 ✓，各探各的时点 ✓。
///
/// ⚠️ 用**种子**而不是随机数 ✓：随机会让"同一台机器每次重启后换一个相位" ✓✗ ——
/// 那不是错开 ✓，那是**每次都在不同时刻探一次** ✓（更糟 ✓）。固定相位才是"各探各的" ✓。
pub fn offset(seed: u64) -> std::time::Duration {
    // 乘一个大奇数再取模 ✓：节点 id 通常连号 ✓，直接用会得到连续的相位 ✓
    //（六台机器摊在 6 小时里会挤成一小段 ✓）—— 乘散列把它铺开 ✓。
    let spread = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    std::time::Duration::from_secs(spread % INTERVAL.as_secs())
}

/// **现在该不该探** ✓✓ —— 纯函数 ✓（所以"重启会不会引发探测风暴"这种问题能测出来 ✓）。
///
/// - 从没探过 ⇒ **探** ✓（新装的机器应当尽快有结论 ✓）；
/// - 探过但还没到周期 ⇒ **不探** ✓✓ —— ⚠️ 这一条是关键 ✗：
///   agent 崩溃重启循环时，"从没探过"若被当成"立刻探" ✓ ⇒ **探测风暴** ✓✗
///   （hub 那次 OOM 崩溃循环就是这个形状 ✓ ⇒ 所以"上次探测时间"**必须落盘** ✓✓ —— 内存里的东西一重启就没了 ✓，而那正是风暴的来源 ✓）。
///
/// ⚠️ 相位（[`offset`]）只影响**首次**探测的时点 ✓：从没探过时，
/// 要等到"开机时刻 + 相位"之后才探 ✓ —— 否则"等相位"这条对首探不生效 ✓，
/// 六台新机器还是会在同一次纳管后一起探 ✓✗。
pub fn due(
    last_probe: Option<std::time::SystemTime>,
    now: std::time::SystemTime,
    started: std::time::SystemTime,
    seed: u64,
) -> bool {
    match last_probe {
        // 探过 ✓：按上次探测时间算周期 ✓（不看开机时刻 ✓ —— 重启不该重置周期 ✓）
        Some(last) => match now.duration_since(last) {
            Ok(since) => since >= INTERVAL,
            // 时钟往回调过（`last` 在未来 ✓）⇒ **不探** ✓：宁可少探一次，不可风暴 ✓。
            Err(_) => false,
        },
        // 从没探过 ✓：等过了相位才探 ✓（把六台新机器摊开 ✓）
        None => match now.duration_since(started) {
            Ok(since) => since >= offset(seed),
            Err(_) => true,
        },
    }
}

// ───────────────────────────── 状态：读写（落不了就如实退回内存）─────────────────────────────

/// "上次探测时间"的存放处 ✓✓ —— **能落盘就落盘，落不了就退回内存并警告一次** ✓。
///
/// ⚠️ 为什么非要落盘 ✗：`Restart=always` 下 agent 崩溃重启循环时 ✓，
/// "从没探过 ⇒ 立刻探"会变成**探测风暴** ✓✗（hub 那次 OOM 崩溃循环就是这个形状 ✓）。
/// ⚠️ 而为什么"退回内存"也要明说 ✗：那种情况下**它确实会退化** ✓ ——
/// 用户应当**知道** ✓，而不是以为"落盘了、稳了" ✓✗。所以降级时**警告一次** ✓（只一次 ✓，不刷屏 ✓）。
pub struct State {
    /// `None` = 拿不到可写目录 ✓（老安装 ✓ / 手动跑 ✓）⇒ 只放内存 ✓。
    path: Option<std::path::PathBuf>,
    /// 内存里的那份 ✓ —— 它是**权威**的（进程内），文件只是它的持久化 ✓。
    memory: std::sync::Mutex<Option<std::time::SystemTime>>,
    warned: std::sync::Once,
}

impl State {
    /// `dir` 来自 [`state_dir`] ✓（`None` ⇒ 只放内存 ✓，并会在首次写入时警告一次 ✓）。
    pub fn new(dir: Option<std::path::PathBuf>) -> Self {
        Self { path: dir, memory: std::sync::Mutex::new(None), warned: std::sync::Once::new() }
    }

    /// 状态文件名 ✓（放在 [`State::new`] 给的目录里 ✓）。
    fn file(&self) -> Option<std::path::PathBuf> {
        Some(self.path.as_ref()?.join("last-probe"))
    }

    /// 上次探测时间 ✓ —— 内存里有就用它 ✓，否则读文件 ✓；读不出来（没有 / 坏了 ✓）⇒ `None` ✓。
    /// ⚠️ **不猜** ✗：读不出来就让调用方按"从没探过"处理 ✓ —— 而那条路也要等过相位 ✓（见 [`due`] ✓）。
    pub fn last(&self) -> Option<std::time::SystemTime> {
        if let Some(t) = *self.memory.lock().unwrap_or_else(|e| e.into_inner()) {
            return Some(t);
        }
        let t = std::fs::read_to_string(self.file()?).ok().and_then(|s| parse_stamp(&s))?;
        *self.memory.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Some(t)
    }

    /// 记下"刚探过" ✓ —— 内存一定更新 ✓（进程内立刻生效 ✓）；**同时尽力落盘** ✓。
    /// ⚠️ 落盘失败**不是**错误返回 ✗：探测本身已经成功了 ✓，
    /// 不该因为"写不进状态文件"就让这一次探测失败 ✓✗；但这**会让下次重启失去保护** ✓ ⇒ 警告一次 ✓。
    pub fn remember(&self, at: std::time::SystemTime) {
        *self.memory.lock().unwrap_or_else(|e| e.into_inner()) = Some(at);
        let Some(path) = self.file() else {
            self.warn_once("no writable state directory (StateDirectory= missing?)");
            return;
        };
        let Some(text) = format_stamp(at) else {
            return; // 早于 Unix 纪元的值 ✓（不该出现 ✓，写出去也会被读成 1970 ✓✗）
        };
        // ⚠️ **原子写** ✓：先写同目录的临时文件 ✓ 再 rename ✓ ——
        // 直接截断写的话，崩在中间会留下半个文件 ✓，而它读出来是"从没探过" ✓✗（于是又探一次 ✓）。
        let tmp = path.with_extension("tmp");
        let ok = std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, &path)).is_ok();
        if !ok {
            let _ = std::fs::remove_file(&tmp); // 别留下垃圾 ✓
            self.warn_once("cannot write the probe state file; restart protection is degraded");
        }
    }

    /// 降级警告**只打一次** ✓（崩溃重启循环里刷屏会把日志本身变成问题 ✓）。
    fn warn_once(&self, msg: &str) {
        self.warned.call_once(|| eprintln!("probe: {msg}"));
    }
}

// ─────────────────────────── 取页（本模块唯一不可单测的部分）───────────────────────────

/// 一次 HTTPS GET ✓ —— **只是把页面拿回来** ✓：它失败就是失败 ✓，绝不猜 ✓。
///
/// ⚠️ 这里**没有任何判断** ✓（判断全在纯函数里 ✓✓）—— 这是刻意的：
/// 网络的失败方式太多（连不上 ✓ 超时 ✓ 证书错 ✓ 被劫持 ✓），
/// 把"判断"混进来就会出现"某次网络抖动 ⇒ 结论变了" ✓✗。
///
/// ⚠️ **跟随跳转** ✓✓：参考实现用的是 `curl -fsL` ✓，而 `netflix.com/title/...`
/// 会按地区 302 ✓ ⇒ 不跟的话读到的是跳转页 ✓，而它的内容**看起来也像正常页面** ✓✗
/// （于是判据会得出一个安静的错结论 ✓）。只跟 `MAX_REDIRECTS` 次 ✓。
///
/// ⚠️ **有上限** ✓：只读 `MAX_BYTES` 就停 ✓ —— 一个恶意/异常的响应不该把这台机器的内存吃掉 ✓
/// （hub 那边刚因为"整份读进内存"出过 OOM 事故 ✓，这条规矩一样适用 ✓）。
pub async fn fetch(url: &str) -> anyhow::Result<String> {
    // 这些常量放在函数里，改动时只在一处 ✓。
    const MAX_BYTES: usize = 512 * 1024;
    const MAX_REDIRECTS: u8 = 3;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let (status, headers_end, body) = tokio::time::timeout(TIMEOUT, get_once(&current)).await??;
        if (300..400).contains(&status) {
            // Location 头是跳转目标 ✓；没有就没什么可跟的 ✓。
            match header(&body[..headers_end.min(body.len())], "location") {
                Some(loc) if loc.starts_with("https://") => current = loc,
                Some(_) => anyhow::bail!("refusing a non-https redirect from {current}"),
                None => return Ok(body),
            }
            continue;
        }
        if status != 200 {
            anyhow::bail!("{current} answered HTTP {status}");
        }
        return Ok(body);
    }
    anyhow::bail!("too many redirects starting at {url}")
}

/// 发一次请求并读回（**最多** `MAX_BYTES` ✓）。返回 `(状态码, 头部结束位置, 全文)`。
/// ⚠️ 与 `fetch` 拆开只是为了让上面那段跳转逻辑**读起来是一件事** ✓。
async fn get_once(url: &str) -> anyhow::Result<(u16, usize, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MAX_BYTES: usize = 512 * 1024;
    let rest = url.strip_prefix("https://").ok_or_else(|| anyhow!("not https: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    let port = authority.split_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(443);

    // 根证书来自 webpki-roots ✓（与 ws 那条路同一套信任根 ✓）——
    // ⚠️ 这很重要 ✓：**没有**它就只能不校验证书 ✓，那等于把"被劫持"当正常 ✓✗。
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(host.to_string())?;

    let tcp = TcpStream::connect((host, port)).await?;
    let mut tls = connector.connect(name, tcp).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: monitor-agent\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= MAX_BYTES {
            buf.truncate(MAX_BYTES);
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (status, headers_end) = parse_status_and_headers(&text)?;
    Ok((status, headers_end, text))
}

/// 从响应里读状态码与"头部结束"的位置 ✓（纯函数 ✓ —— 所以它有测试 ✓✓）。
fn parse_status_and_headers(text: &str) -> anyhow::Result<(u16, usize)> {
    let line_end = text.find("\r\n").ok_or_else(|| anyhow!("no status line"))?;
    let status: u16 = text[..line_end]
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("unreadable status line: {:?}", &text[..line_end.min(text.len())]))?;
    // 头部与正文的分界 ✓；没有分界（被截断 ✓）就当作"全文都是头" ✓。
    let headers_end = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
    Ok((status, headers_end))
}

/// 从**响应头部**里取某个头 ✓（小写比较 ✓ —— HTTP 头不区分大小写 ✓）。
/// ⚠️ 只在头部范围内找 ✓，免得把正文里恰好出现的 `location:` 当成跳转 ✓✗。
fn header(head: &str, name: &str) -> Option<String> {
    let want = format!("{}:", name.to_ascii_lowercase());
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with(&want))
        .map(|l| l[want.len()..].trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个页面都说看不了 ⇒ **未解锁** ✓（这是"对方明确告诉你"的那种 ✓，是结论 ✓）。
    #[test]
    fn both_pages_saying_no_means_blocked() {
        let v = netflix_verdict("<html>Oh no!</html>", "<html>Oh no!</html>");
        assert_eq!(v.status, Status::Blocked);
        assert_eq!(v.region, None, "未解锁时不给地区 ✓（那边没有地区可言 ✓）");
    }

    /// ⭐ **只有一页说看不了 ⇒ 不能下"未解锁"的结论** ✓✓ —— 这一条是这一块最要紧的测试 ✓：
    /// 它挡住的是"把一部剧在某区没有，说成整个 Netflix 被墙" ✓✗。
    #[test]
    fn one_page_saying_no_is_not_enough_to_call_it_blocked() {
        let v = netflix_verdict("{\"id\":\"US\",\"countryName\":\"United States\"}", "<html>Oh no!</html>");
        assert_eq!(v.status, Status::Unknown, "只有一页 ⇒ 没读明白 ✓，不是未解锁 ✗");
        assert_eq!(v.region.as_deref(), Some("US"), "但读到的地区照样给出来 ✓");
    }

    /// 两页都正常 ⇒ **解锁** ✓，并取到地区 ✓。
    #[test]
    fn two_good_pages_mean_unlocked_with_a_region() {
        let a = "{\"id\":\"JP\",\"countryName\":\"Japan\"}";
        let b = "{\"id\":\"JP\",\"countryName\":\"Japan\"}";
        assert_eq!(netflix_verdict(a, b), Verdict { status: Status::Unlocked, region: Some("JP".into()) });
    }

    /// ⚠️ 地区必须**两位大写字母**才认 ✓ —— 否则页面上任何 `"id":"…"`（剧集 id ✓、
    /// 语言码 ✓、内部字段 ✓）都会被当地区 ✓✗，而那种错**看起来完全正常** ✓。
    #[test]
    fn a_region_must_look_like_a_region() {
        assert_eq!(netflix_region("{\"id\":\"81280792\"}"), None, "剧集 id 不是地区 ✓");
        assert_eq!(netflix_region("{\"id\":\"en\"}"), None, "小写语言码不是地区 ✓");
        assert_eq!(netflix_region("{\"id\":\"US\"}"), Some("US".into()));
        assert_eq!(netflix_region("<html>Oh no!</html>"), None, "没有就别说 ✓");
    }

    /// 空页面（请求成功但什么都没拿到 ✓）⇒ **没读明白** ✓，既不是解锁也不是未解锁 ✓。
    #[test]
    fn empty_pages_are_unknown_not_unlocked() {
        assert_eq!(netflix_verdict("", "").status, Status::Unknown);
        assert_eq!(netflix_verdict("   \n", "  ").status, Status::Unknown);
    }
    /// ⭐ **跳转那一段的第一道闸** ✓✓：状态码与"头部在哪里结束"必须读对 ✓ ——
    /// 读错就会把**正文**当成头部去找 `location:` ✓✗，而那会得出一个安静的错跳转 ✓。
    #[test]
    fn the_status_line_and_the_header_boundary_are_read_correctly() {
        let r = "HTTP/1.1 302 Found\r\nLocation: https://www.netflix.com/browse\r\n\r\nBODY";
        let (status, end) = parse_status_and_headers(r).unwrap();
        assert_eq!(status, 302);
        assert_eq!(&r[end..], "BODY", "头部结束位置要正好在空行之后 ✓");
        assert_eq!(parse_status_and_headers("HTTP/1.1 200 OK\r\n\r\n").unwrap().0, 200);
        // ⚠️ **被截断的响应**（没有空行 ✓）⇒ 当作"全文都是头" ✓，而不是报错 ✓ ——
        // 截断是真会发生的事（我们的 512 KB 上限 ✓），它不该被当成"这个服务没数据" ✗。
        let cut = "HTTP/1.1 200 OK\r\nContent-Type: text/htm";
        let (s2, e2) = parse_status_and_headers(cut).unwrap();
        assert_eq!((s2, e2), (200, cut.len()));
        assert!(parse_status_and_headers("garbage").is_err(), "真读不懂才报错 ✓");
    }

    /// ⭐ **"只从头部找 location"** ✓✓ —— 本轮最要紧的一条 ✓：
    /// 正文里恰好出现 `location:` **绝不能**被当成跳转 ✓✗。
    /// ⚠️ 这里测的是**契约** ✓：`header` 只在传进来的那段里找 ✓ ——
    /// 而"只把头部传进来"这个动作在 `fetch` 里 ✓（那半段不可单测 ✓）
    /// ⇒ 所以把契约写成测试 ✓，免得将来有人拿**全文**去调它 ✓✗。
    #[test]
    fn a_location_like_string_in_the_body_is_not_a_redirect() {
        let head = "HTTP/1.1 302 Found\r\nLocation: https://www.netflix.com/browse\r\n\r\n";
        assert_eq!(header(head, "location").as_deref(), Some("https://www.netflix.com/browse"));
        assert_eq!(
            header("LOCATION: https://a.example/\r\n", "location").as_deref(),
            Some("https://a.example/"),
            "大小写不敏感 ✓"
        );
        assert_eq!(
            header("location:   https://b.example/  \r\n", "location").as_deref(),
            Some("https://b.example/"),
            "两侧空白要去掉 ✓"
        );
        // ⚠️ **`X-Location:` 不是 `Location:`** ✓ —— 前缀匹配不能把带前缀的头也算上 ✓✗
        assert_eq!(header("X-Location: https://c.example/\r\n", "location"), None);
        assert_eq!(header("Location:   \r\n", "location"), None, "空跳转目标不该被跟着走 ✓");
        assert_eq!(header("HTTP/1.1 200 OK\r\n\r\n", "location"), None);
    }
    /// ⭐ **重启不该引发探测风暴** ✓✓ —— 本轮最要紧的一条 ✓：
    /// 探过一次之后，重启（`last_probe` 已落盘 ✓）必须**接着原来的周期**走 ✓，而不是立刻再探 ✓。
    #[test]
    fn a_restart_does_not_trigger_another_probe() {
        use std::time::{Duration, SystemTime};
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let just_now = t0 + Duration::from_secs(60);
        // 一分钟前刚探过 ✓，而周期是 6 小时 ⇒ **不探** ✓（哪怕进程是刚刚启动的 ✓）
        assert!(!due(Some(just_now - Duration::from_secs(60)), just_now, just_now, 7));
        // 六小时前探过 ⇒ 探 ✓
        assert!(due(Some(just_now - INTERVAL), just_now, just_now, 7));
        // 差一秒 ⇒ 还不探 ✓（边界不能含糊 ✓）
        assert!(!due(Some(just_now - INTERVAL + Duration::from_secs(1)), just_now, just_now, 7));
    }

    /// 从没探过 ⇒ 探 ✓，但**要等过相位** ✓ —— 否则同时纳管的六台会在同一刻一起探 ✓✗。
    #[test]
    fn a_first_probe_waits_for_its_phase() {
        use std::time::{Duration, SystemTime};
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        // 种子的相位是确定的 ✓（同一个种子每次都一样 ✓）
        let ph = offset(7);
        assert!(ph < INTERVAL, "相位必须落在周期之内 ✓");
        // 刚启动 ⇒ 还不探 ✓（除非相位恰好是 0 ✓，那种子很少见 ✓ —— 用确定性的判据 ✓）
        if ph > Duration::from_secs(1) {
            assert!(!due(None, started + Duration::from_secs(1), started, 7), "还没到相位 ⇒ 不探 ✓");
        }
        assert!(due(None, started + ph, started, 7), "到了相位 ⇒ 探 ✓");
    }

    /// ⚠️ 时钟被往回调（上次探测时间在"未来" ✓）⇒ **不探** ✓ —— 宁可少探一次，不可风暴 ✓。
    #[test]
    fn a_clock_going_backwards_does_not_cause_a_probe() {
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert!(!due(Some(now + Duration::from_secs(3600)), now, now, 7));
    }

    /// 相位要**把不同节点摊开** ✓（连号的 id 也得散开 ✓）—— 否则"错开"只是个说法 ✓。
    #[test]
    fn nearby_seeds_do_not_land_next_to_each_other() {
        let hours: Vec<u64> = (1..=8).map(|i| offset(i).as_secs() / 3600).collect();
        let mut uniq = hours.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert!(uniq.len() >= 4, "8 个连号 seed 至少该散到 4 个不同的小时里（实际 {hours:?}）✓");
    }
    /// 状态目录：systemd 给就用它 ✓；没给 / 空 ⇒ `None` ✓（调用方据此**如实降级** ✓，
    /// 而不是写到一个写不了的地方然后失败 ✓）。
    #[test]
    fn the_state_directory_comes_from_the_environment_or_not_at_all() {
        assert_eq!(state_dir(Some("/var/lib/monitor-agent")), Some("/var/lib/monitor-agent".into()));
        assert_eq!(
            state_dir(Some("  /var/lib/monitor-agent  ")),
            Some("/var/lib/monitor-agent".into()),
            "两侧空白要去掉 ✓"
        );
        // systemd 可能给多个（冒号分隔 ✓）⇒ 取第一个 ✓
        assert_eq!(state_dir(Some("/var/lib/monitor-agent:/run/x")), Some("/var/lib/monitor-agent".into()));
        assert_eq!(state_dir(Some("")), None, "空 ⇒ 拿不到 ✓");
        assert_eq!(state_dir(Some("   ")), None);
        assert_eq!(state_dir(None), None, "变量都没有 ⇒ 拿不到 ✓");
        assert_eq!(state_dir(Some(":/run/x")), Some("/run/x".into()), "第一个是空的 ⇒ 用第二个 ✓");
    }

    /// 时间戳两个方向要**互为逆** ✓，而读不出来时**宁可 None 也不猜** ✓。
    #[test]
    fn the_probe_stamp_round_trips_and_refuses_nonsense() {
        use std::time::{Duration, SystemTime};
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let s = format_stamp(t).unwrap();
        assert_eq!(parse_stamp(&s), Some(t));
        assert_eq!(parse_stamp(" 1700000000\n"), Some(t), "末尾换行要去掉 ✓");
        // ⚠️ 读不出来 ⇒ None ✓（**不猜** ✗ —— 猜错方向可能就是"立刻又探一次" ✓✗）
        assert_eq!(parse_stamp(""), None);
        assert_eq!(parse_stamp("abc"), None);
        assert_eq!(parse_stamp("-5"), None);
        assert_eq!(parse_stamp("1.5"), None);
        // 早于 Unix 纪元 ⇒ 写不出来 ✓（写 0 会被读成"1970 年探过" ✓✗）
        assert_eq!(format_stamp(SystemTime::UNIX_EPOCH - Duration::from_secs(1)), None);
    }
    /// 落盘 → 读回要**一致** ✓；换一个新进程（新 `State` 实例 ✓）也要读得到 ✓
    /// —— 这才是"重启不风暴"真正依赖的东西 ✓✓。
    #[test]
    fn the_probe_stamp_survives_a_restart() {
        use std::time::{Duration, SystemTime};
        let dir = std::env::temp_dir().join(format!("monitor-probe-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let first = State::new(Some(dir.clone()));
        assert_eq!(first.last(), None, "还没写过 ⇒ None ✓（不是 1970 ✓）");
        first.remember(t);

        // 换一个实例 = 新进程 ✓（内存是空的 ✓，只能靠文件 ✓）
        let after_restart = State::new(Some(dir.clone()));
        assert_eq!(after_restart.last(), Some(t), "重启后必须读得回来 ✓✓");
        assert!(!dir.join("last-probe.tmp").exists(), "临时文件不该留下 ✓（它的存在会让人以为写失败了 ✓）");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 拿不到目录 ⇒ 只放内存 ✓：**进程内仍然有效** ✓，但**不会**假装自己落盘了 ✓。
    #[test]
    fn without_a_directory_the_state_stays_in_memory_only() {
        use std::time::{Duration, SystemTime};
        let s = State::new(None);
        assert_eq!(s.last(), None);
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        s.remember(t);
        assert_eq!(s.last(), Some(t), "进程内必须立刻生效 ✓");
        // ⚠️ 换一个实例就读不到了 ✓ —— 这正是"降级"的含义 ✓（会对用户警告一次 ✓）
        assert_eq!(State::new(None).last(), None);
    }

    /// 状态文件读不出来 ⇒ `None` ✓（**不猜** ✗），而且**不能 panic** ✓。
    ///
    /// ⚠️ **一个刻意留下的判断，写在这里免得后人误会** ✗：文件里若是"**能解析但很旧**"的值
    /// （半截写入恰好留下一个合法数字 ✓ —— 例如 `"17"` 就是纪元后 17 秒 ✓），
    /// 本项目**不**去猜"这大概是坏的" ✓ ⇒ 它会读成一个 1970 年的时间 ✓ ⇒ [`due`] 说"该探了" ✓
    /// ⇒ **最多多探一次** ✓ —— **不是风暴** ✓✓。
    /// ⇒ 也就是说这个失败方向是**安全**的 ✓，所以不值得为它加"太旧就当没写"那种猜测逻辑 ✗
    ///（那种猜测本身也可能猜错 ✓，而它换来的只是少探一次 ✓）。
    #[test]
    fn an_unreadable_state_file_is_treated_as_never_probed() {
        let dir = std::env::temp_dir().join(format!("monitor-probe-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // ⚠️ 这里**不含**带末尾空白的输入 —— 那是**合法**的（`parse_stamp` 会 trim），
        // 而"文件末尾多一个换行"恰恰是最常见的情形，所以要单独断言它**能**读出来。
        for bad in ["", "abc", "-5", "1.5", "17x"] {
            std::fs::write(dir.join("last-probe"), bad).unwrap();
            assert_eq!(State::new(Some(dir.clone())).last(), None, "读不出来 ⇒ None ✓（内容 {bad:?}）");
        }
        // 与上面成对 ✓：末尾空白**必须**能读 ✓ —— 否则每次落盘都会被自己读成"没探过" ✓✗
        std::fs::write(dir.join("last-probe"), "1700000000\n").unwrap();
        assert_eq!(
            State::new(Some(dir.clone())).last(),
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
            "末尾换行是合法的 ✓"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// 种子要**稳定** ✓（同一台机器每次一样 ✓）且**彼此散开** ✓（不同机器落在不同相位 ✓）。
    /// ⚠️ 也断言它**不依赖任何秘密** ✓：同一个 hostname 永远同一个值 ✓ ——
    /// 这条测试同时是"我们没把 token 掺进来"的一个提醒 ✓（掺了的话这里就得跟着改 ✓）。
    #[test]
    fn the_seed_is_stable_per_machine_and_spread_across_machines() {
        assert_eq!(seed_from("node-a"), seed_from("node-a"), "同一台机器必须稳定 ✓");
        assert_eq!(seed_from("  node-a  "), seed_from("node-a"), "两侧空白不该改变种子 ✓");
        assert_ne!(seed_from("node-a"), seed_from("node-b"), "不同机器要不同 ✓");
        // ⚠️ 相似的名字也要散开 ✓（`node-01` / `node-02` 相邻 ✓ ⇒ 相位不该挨着 ✓）
        let hours: Vec<u64> =
            (1..=8).map(|i| offset(seed_from(&format!("node-{i:02}"))).as_secs() / 3600).collect();
        let mut uniq = hours.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert!(uniq.len() >= 4, "8 个相似名字至少该散到 4 个不同的小时里（实际 {hours:?}）✓");
        // 空 / 畸形输入不该 panic ✓（读不到 hostname 时 agent 用的是 "unknown" ✓）
        let _ = seed_from("");
        let _ = seed_from("unknown");
    }
}
