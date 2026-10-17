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
    /// **只有网页能用** ✓✓（用户定的第五档 ✓）：ChatGPT 会分别探 API 与 iOS 端 ✓，
    /// 于是可能出现"网页能开、App 打不开" ✓ —— 这既不是解锁 ✓，也不是未解锁 ✓。
    Web,
    /// **只有 App 能用** ✓✓（第六档 ✓）：与 [`Status::Web`] 相对 ✓。
    App,
    /// **中国版** ✓✓（第七档 ✓）：YouTube 的响应来自 `www.google.cn` ✓
    ///（参考实现把地区**硬写成 `[CN]`** ✓ —— 那不是猜的 ✓，是"它给的就是中国版"这个事实 ✓）。
    Cn,
    /// **能用，但 Premium 会员买不到** ✓✓（第八档 ✓）：
    /// 视频能看 ✓，只是这个国家不卖会员 ✓ —— ⚠️ 它**能用** ✗，别当成"没解锁" ✓✗。
    /// **解锁、但只有自制剧能看** ✓✓（第九档 ✓）：
    /// Netflix 两页**都**说看不了 ⇒ 参考实现判 `NF.Only` ✓（那一档**能用** ✗ ——
    /// 只是自制剧之外的内容看不了 ✓）⇒ ⚠️ **不是** `Blocked` ✗（判成红的会让人以为整台被墙 ✓✗）。
    Org,
    NoPrem,
    /// **解锁、但对方把这个地址识别成机房** ✓✓（用户定的第四档 ✓）。
    /// ⚠️ 它与 `Unlocked` **不是一回事** ✗：机房 IP 在很多服务上吃亏 ✓，
    /// 而这正是运维想知道的 ✓；也与 `Blocked` 不同 ✓ ⇒ 独立一档 ✓。
    Idc,
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
    // ⚠️⚠️ **两个页面都得先过地板** ✗✗ —— 否则两个机器人页（都不含 `Oh no!` ✓）
    // 会一路走到最后那个 `else` ⇒ 判成「**解锁**」✓✗ —— 一个**绿色的**错值 ✓（比红的更坏 ✓）。
    if !looks_like_a_real_page(page_a) || !looks_like_a_real_page(page_b) {
        return Verdict { status: Status::Unknown, region: None };
    }
    // ⚠️ 两页**都**说看不了 ⇒ 参考实现判 **`org`（NF.Only / 仅自制）** ✓✓ —— 不是 blocked ✗：
    // 那一档**能用** ✓，只是自制剧之外看不了 ✓（用户那张参考图上写的就是「仅自制」✓）。
    let both_say_no = page_a.contains("Oh no!") && page_b.contains("Oh no!");
    let status = if both_say_no {
        Status::Org
    } else if page_a.contains("Oh no!") || page_b.contains("Oh no!") {
        // ⚠️ **只有一个**页面说看不了 ⇒ 说不清 ✓（可能是那一部剧在这个区没有 ✓，
        // 也可能另一页没取到 ✓）⇒ 如实说"没读明白" ✓，**不猜** ✗。
        Status::Unknown
    } else if page_a.trim().is_empty() && page_b.trim().is_empty() {
        Status::Unknown
    } else {
        Status::Unlocked
    };
    // 地区只在能用那两档给：参考里 blocked 与 failed 都不给地区。
    // 给的话会让人以为这台机器还能看某些内容，而它其实什么也看不了。
    let region = match status {
        Status::Unlocked | Status::Org => netflix_region(page_a).or_else(|| netflix_region(page_b)),
        _ => None,
    };
    Verdict { status, region }
}

/// 从页面里取地区码 ✓（`"id":"US"` 紧邻 `"countryName"` 的那一处 ✓，照参考的正则 ✓）。
/// 取不到 ⇒ `None` ✓（**不编** ✗）。
fn netflix_region(page: &str) -> Option<String> {
    // 取最后一处：参考那行是 sed 的贪婪匹配，拿到的就是最后一处。
    // 与 YouTube / TikTok 同一规矩（先给值、后给空 的页面会分叉）。
    // 形状检查照旧：必须两位大写，否则那只是别的 id 字段。
    // 参考还要求 id 与 countryName 相邻，这一条刻意没跟（更宽松，但靠形状兜住）。
    const KEY: &str = "\"id\":\"";
    let mut found: Option<String> = None;
    let mut from = 0usize;
    while let Some(i) = page[from..].find(KEY) {
        let start = from + i + KEY.len();
        from = start;
        let Some(end) = page[start..].find('"') else { continue };
        let code = &page[start..start + end];
        found = if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
            Some(code.to_string())
        } else {
            None
        };
    }
    found
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

// ─────────────────────────── 上报的报文（形状必须与 hub 的白名单逐字一致）───────────────────────────

/// 把一次结论变成**要发给 hub 的报文** ✓✓ —— 纯函数 ✓，而且**通用** ✓：
/// 服务名是参数 ✓ ⇒ 加一个服务**不必再抄一份** ✗（抄一份就会有两处要同步 ✓，迟早漏一处 ✓）。
///
/// ⚠️⚠️ **状态字符串必须与 hub 侧的白名单逐字一致** ✗✗（见 `agent_ws::sanitize_probe` ✓）：
/// `unlocked` ✓ / `blocked` ✓ / `unknown` ✓ / **`idc`** ✓（第四档 ✓）——
/// 差一个字母 ⇒ hub 把整条丢掉 ✓ ⇒ 面板上**安静地什么都没有** ✓✗（没有任何报错 ✓）。
pub fn verdict_json(service: &str, v: &Verdict) -> serde_json::Value {
    let status = match v.status {
        Status::Unlocked => "unlocked",
        Status::Blocked => "blocked",
        Status::Unknown => "unknown",
        Status::Idc => "idc",
        Status::Web => "web",
        Status::App => "app",
        Status::Cn => "cn",
        Status::Org => "org",
        Status::NoPrem => "noprem",
    };
    let mut item = serde_json::Map::new();
    item.insert("status".into(), serde_json::json!(status));
    if let Some(r) = &v.region {
        item.insert("region".into(), serde_json::json!(r));
    }
    serde_json::json!({ service: serde_json::Value::Object(item) })
}

/// 把一次结论变成**要发给 hub 的报文** ✓✓ —— 纯函数 ✓（所以那几个字面量能被钉死 ✓）。
/// 一次响应最多读多少字节 ✓ —— **一处定义** ✓（`fetch` 与 `get_once` 都用它 ✓）。
/// ⚠️ 写在两处会漂移 ✓：改了一处、另一处还是旧值 ✓，而那种不一致**不报错** ✓✗。
const MAX_BYTES: usize = 512 * 1024;

/// ⚠️⚠️ **YouTube 单独的上限** ✗✗ —— 它的 `ad-free` 出现在**字节 813,352**（整页 941,197 ✓，
/// 2026-10-13 实测 ✓），而上面的全局 `MAX_BYTES` 是 512 KB ⇒ **三个标记一个都读不到** ✓✗
/// ⇒ 这个服务此前**永远判"没读明白"** ✓，而且**看不出来** ✓（面板上就是一个灰胶囊 ✓）。
/// ⚠️ **不抬全局上限** ✗✗：那个 512 KB 是有理由的 ✓（整份读进内存出过 OOM 事故 ✓）——
/// 这里只给**这一个**服务放开 ✓，并且配合 [`youtube_decided`] 的"够了就停" ✓
/// ⇒ 判中国/禁会员时**几乎立刻收手** ✓，只有"解锁"那一档才真的要读到 ~820 KB ✓。
const YOUTUBE_MAX_BYTES: usize = 2 * 1024 * 1024;

/// ⚠️⚠️ **Netflix 单独的上限** ✗✗ —— 它的两个 title 页面实测是 **2.2–2.3 MB**
///（2026-10-15 ✓ 从代理出口实测：2,287,053 与 2,307,829 字节 ✓），
/// 而默认的 `MAX_BYTES` 是 512 KB ⇒ 只读到前 512 KB ✓✗。
/// ⭐ 诊断把它钉死了 ✓：`--probe-once` 打出来的是 `bytes=524034`（≈512 KiB 那个上限 ✓），
/// 两页都是这个数 ⇒ 读不到 `Oh no!`、也读不到地区 ⇒ 判成"解锁" ✓✗。
/// ⚠️ 这已经是**第二次**同一个教训 ✗：YouTube 那次也是 512 KB 不够 ✓。
/// ⇒ 所以规矩记在这里 ✓：**每个服务各自定窗口，按实测的页面大小给足余量** ✓；
///    默认那个 512 KB 只适用于小页面 ✓。
const NETFLIX_MAX_BYTES: usize = 4 * 1024 * 1024;

/// ⚠️⚠️ **"看着就不像产品页"的响应，不许被读成结论** ✗✗ —— 这一条治的是一整类**安静的错值** ✓：
/// 限流页 ✓ 机器人页 ✓ 网关错误页 ✓ **都是 200** ✓，正文很小 ✓，里面当然也没有我们要找的标记 ✓
/// ⇒ 判据就会得出"**未解锁**"（甚至"解锁" ✓✗）—— ⭐ 一个**看起来很正常的错结论** ✓。
/// ⚠️ 用户生产上就撞到过 ✓：面板显示 PrimeVideo「未解锁」✗，而同一台机器上参考实现读到的
///        是「**解锁 [US]**」✓（我实测那台机器取到的是 200 + `currentTerritory` 4 次 ✓）。
///
/// ⚠️ 阈值 **8 KB** ✓ 是**实测选出来的** ✓（2026-10-13 ✓，三个出口）：
///   · 真实页面：**506 KB / 620 KB / 634 KB / 944 KB** ✓（PrimeVideo / YouTube ✓）
///   · 一次限流：**521 字节** ✓（正文只有 521 ✓）
///   ⇒ 两边差**三个数量级** ✓，8 KB 落在中间、离两边都远 ✓。
///
/// ⚠️ 这是**启发式** ✗ —— 它做不到"认出每一个机器人页" ✓，它只做一件事 ✓：
/// **明显不可能是产品页的东西，不许变成结论** ✓（宁可说"没读明白" ✓）。
/// ⚠️ ⚠️ 它**只适用于 HTML 页面** ✗✗ —— 别拿它去量 JSON 接口 ✓
///（ChatGPT 那个 `compliance/cookie_requirements` 正常就只回 **38 字节** ✓，
///  拿页面尺度去量它会把**正常**判成异常 ✓✗）。
const PAGE_FLOOR: usize = 8 * 1024;

/// 这个响应**够不够格当产品页** ✓（见 [`PAGE_FLOOR`] ✓）。纯函数 ✓ 所以有测试 ✓。
fn looks_like_a_real_page(body: &str) -> bool {
    body.len() >= PAGE_FLOOR
}

// ─────────────────────── YouTube（四档；其中两档是"能用但有条件"）───────────────────────

/// YouTube 要取的地址 ✓（照参考实现 ✓ —— 它带一串 cookie 与 `Accept-Language: en` ✓）。
pub const YOUTUBE_URL: &str = "https://www.youtube.com/premium";

/// 那两个请求头 ✓（⚠️ 参考里**必须有** ✓ —— 不带 `Accept-Language: en` 时页面语言不同 ✓，
/// 判据里那几个字符串就对不上了 ✓✗）。多行头块 ✓（[`fetch_with`] 会把整段塞进请求 ✓）。
pub const YOUTUBE_HEADERS: &str = "Accept-Language: en\r\nCookie: YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai; _gcl_au=1.1.1809531354.1646633279";

/// YouTube 的判据 ✓✓ —— 纯函数 ✓。
///
/// 参考实现的做法 ✓（逐行读出来的 ✓），顺序**刻意如此** ✗：
/// 1. ⚠️ **中国版不在这个函数里** ✗✓ —— 它由**最终落在哪个主机**判定 ✓
///    （[`youtube_is_cn_final`] ✓，调用方先判它 ✓，地区硬写 `CN` ✓）；
///    ⭐ 从前这里是"响应里出现 `www.google.cn`" ✗，而那是个**误报的来源** ✓（见那个函数的注释 ✓）；
/// 2. 出现 `Premium is not available in your country` ⇒ **能用但买不到会员**
///    （[`Status::NoPrem`] ✓✓ —— ⚠️ 它**能用** ✗）；
/// 3. 出现 `ad-free` 且能取到 `"contentRegion":"XX"` ⇒ **解锁** ✓（地区就是它 ✓）；
/// 4. 出现 `ad-free` 但**取不到地区** ⇒ **仍然解锁** ✓✓（地区留空 ✓ ——
///    **不因为缺一格就改判** ✓，与 Netflix/Reddit 同一条规矩 ✓）；
/// 5. 其它 ⇒ **不猜** ✓（`Unknown` ✓ —— 既不是"能用"也不是"不能用" ✓）。
///
/// ⚠️ **顺序与参考实现一字不差** ✓（cn ⇒ noprem ⇒ ad-free ⇒ else ✓）。
/// ⚠️ 我原先在这里写的理由是"中国版页面里也可能出现 `ad-free`，所以顺序致命" ✗ ——
/// **那条理由未经验证** ✗（`www.google.cn` 那条出口测不到 ✓）。顺序**照参考保留** ✓，
/// 但理由换成一个站得住的 ✓：**参考就是这么排的** ✓，而"跟着参考"本身可复核 ✓；
/// 至于它**为什么**更对 ✓，在真测到之前**不写进注释** ✓（否则下一个人会把它当结论 ✓✗）。
pub fn youtube_verdict(body: &str) -> Verdict {
    // ⚠️⚠️ 这里**从前有一条**"正文含 `www.google.cn` ⇒ 中国版" ✗✗ —— **删掉了** ✓：
    // 那是**误报的来源** ✓（用户生产上就撞到过 ✓：正文里 0 次，面板却报「中国区」✗）。
    // ⭐ 中国版现在**只由最终主机判定** ✓ ⇒ 见 [`youtube_is_cn_final`] ✓（调用方先判它 ✓）。
    if body.contains("Premium is not available in your country") {
        return Verdict { status: Status::NoPrem, region: None };
    }
    if body.contains("ad-free") {
        return Verdict { status: Status::Unlocked, region: youtube_region(body) };
    }
    Verdict { status: Status::Unknown, region: None }
}

/// 从一个 URL 里取**主机名** ✓（纯函数 ✓ 所以有测试 ✓）：去掉协议 ✓ 端口 ✓ 路径 ✓ 查询 ✓，
/// 并且**转小写** ✓（主机名不区分大小写 ✓）。
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// ⭐⭐ **"中国版"的唯一凭据：我们最后落在了 `google.cn`** ✓✓ ——
/// ⚠️⚠️ 从前它是**正文里有没有 `www.google.cn`** ✗✗，而那是个**误报的来源** ✓：
/// Google 自己的页面 ✓ hreflang 链接 ✓ 缓存片段 ✓ 里都可能有那个字符串 ✓。
/// ⭐ 实测（2026-10-13 ✓，用户在**生产那台 US 机器**上跑的 ✓）：
/// 面板显示「**中国区**」✗，而那一页正文里 `www.google.cn` 出现 **0 次** ✓✓；
/// `ad-free` 在 **815,530** 字节处 ✓（说明那页其实是**正常解锁页** ✓）。
/// ⇒ 所以判据必须建立在"**我们被跳到了哪里**"上 ✓ —— 那是**可复核的事实** ✓，
/// 而不是"正文里恰好有某个串" ✓。
/// ⚠️ 用 `== ` 与 `.google.cn` 后缀 ✓ —— 不能用 `contains("google.cn")` ✗
///（`notgoogle.cn` ✓ `google.cn.evil.com` ✓ 都会命中 ✓✗）。
pub fn youtube_is_cn_final(final_url: &str) -> bool {
    host_of(final_url).is_some_and(|h| h == "google.cn" || h.ends_with(".google.cn"))
}

/// YouTube 的判据**到这儿就够了吗** ✓ —— 够了就别把整页读完 ✓✓（省内存 ✓ 也省时间 ✓）。
/// ⚠️ 三种标记**各自需要什么**不一样 ✗：
///   · `www.google.cn` ⇒ 判中国 ✓，地区**硬写 CN** ✓ ⇒ 见到它就能停 ✓；
///   · `Premium is not available in your country` ⇒ 判禁会员 ✓，**没有地区** ✓ ⇒ 见到就能停 ✓；
///   · `ad-free` ⇒ 判解锁 ✓，但同一条判据**还要取地区** ✓ ⇒ 必须**连 `contentRegion` 一起**见到 ✓✗
///     （停早了会把地区弄丢 ✓ —— 而"状态对、地区静默消失"正是本仓最怕的那类错 ✓）。
pub fn youtube_decided(body: &str) -> bool {
    // ⚠️⚠️ **这里没有 `www.google.cn`** ✗✗ —— 它曾经是一条"够了就停"的判据，而
    // `youtube_verdict` 早就把"正文含这个域名 ⇒ 中国版"删掉了（那是误报来源：正文里 0 次，
    // 面板却报「中国区」）。两处不一致的后果是：页面里只要**任何地方**出现这个域名
    // （hreflang 链接、页脚、脚本），我们就在 ~32KB 处停手，而 `ad-free` 在 ~815KB 处
    // ⇒ 判成"没读明白"。这是"先看头部"那次事故的**同一形状**，触发点挪进了正文。
    //
    // 中国版现在**只由最终主机判定**（见 [`youtube_is_cn_final`]）。所以这里只留两条
    // 真正能定案的信号：禁会员那句，以及"ad-free + 地区"同时到位。
    body.contains("Premium is not available in your country")
        || (body.contains("ad-free") && body.contains("\"contentRegion\""))
}

/// 从页面里取 `"contentRegion":"XX"` ✓ —— 形状检查照旧 ✓（两位大写 ✓）。
pub fn youtube_region(body: &str) -> Option<String> {
    const KEY: &str = "\"contentRegion\"";
    // ⚠️ 取**最后一处** ✓✓（参考的 `sed` 里 `.*` 是贪婪的 ⇒ 它取的也是最后一处 ✓）。
    // 实测那页 13 处值全相同 ⇒ 这一条**当前无差别** ✓；但"先给值、后给空"的页面会分叉 ✓
    // ⇒ 既然要对齐参考，就对齐到底 ✓。
    // ⚠️ 形状检查**比参考严** ✓（只收两位大写 ✓；源码 `usa`／`USA` 照收 ✓）——
    // 这是**刻意**的 ✓：hub 那一侧也是这个形状 ✓，宽收进来反而会在别处被丢 ✓。
    let mut found: Option<String> = None;
    let mut from = 0usize;
    while let Some(i) = body[from..].find(KEY) {
        let start = from + i + KEY.len();
        from = start;
        let Some(colon) = body[start..].find(':') else { continue };
        let after_colon = &body[start + colon + 1..];
        let Some(q) = after_colon.find('"') else { continue };
        let after = &after_colon[q + 1..];
        let Some(end) = after.find('"') else { continue };
        let code = &after[..end];
        found = if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
            Some(code.to_string())
        } else {
            None
        };
    }
    found
}

// ───────────────────────────── AmazonPV（最干净的一个：一页定生死）─────────────────────────────

/// Amazon Prime Video 要取的地址 ✓（照参考实现 ✓ —— 一个普通 GET ✓）。
pub const AMAZONPV_URL: &str = "https://www.primevideo.com";

/// AmazonPV 的判据 ✓✓ —— 纯函数 ✓，而且**只用得着三个既有状态** ✓✓
///（不需要任何新档 ✓ —— 这一期里唯一一个这样的服务 ✓）。
///
/// 参考实现的做法 ✓：从 `https://www.primevideo.com` 的响应里取
/// `"currentTerritory": "XX"` ✓ —— **有 ⇒ 解锁** ✓（地区就是它 ✓）；**没有 ⇒ 未解锁** ✓。
///
/// ⚠️ 而"取页失败"**不在这里** ✗：那是调用方的事 ✓（连不上 ⇒ **不报** ✓✗，
/// 因为一次网络故障不是结论 ✓ —— 与 Netflix/TikTok 同一条规矩 ✓）。
pub fn amazonpv_verdict(body: &str) -> Verdict {
    // ⚠️⚠️ **先过那道地板** ✗✗ —— 不然一次限流就会变成"未解锁" ✓（用户撞到过 ✓）。
    if !looks_like_a_real_page(body) {
        return Verdict { status: Status::Unknown, region: None };
    }
    match amazonpv_region(body) {
        Some(r) => Verdict { status: Status::Unlocked, region: Some(r) },
        None => Verdict { status: Status::Blocked, region: None },
    }
}

/// 从响应里取 `"currentTerritory": "XX"` ✓。
/// ⚠️ 形状检查照旧 ✓：**必须两位大写字母** ✓ —— 那两个键名附近还有别的字段 ✓，
/// 不检查形状就会把别的值当地区 ✓✗（一个"看起来很正常"的错值 ✓）。
pub fn amazonpv_region(body: &str) -> Option<String> {
    // ⚠️⚠️ `find("\"currentTerritory\"")` 命中的位置**就是那个左引号本身** ✗
    // ⇒ 若从那里再找下一个引号 ✓，取到的是**键名**（`currentTerritory` ✓）而不是值 ✓✗。
    // ⭐ 这正是两条测试第一版双双失败的原因 ✓（测试是对的 ✓，实现是错的 ✓）。
    // 正确做法 ✓：从**键名之后**继续找 ✓ —— 先找 `:` ✓，再找它后面的第一个引号 ✓。
    let i = body.find("\"currentTerritory\"")? + "\"currentTerritory\"".len();
    let rest = &body[i..];
    let colon = rest.find(':')?;
    let after_colon = &rest[colon + 1..];
    let q = after_colon.find('"')?; // 中间允许空白 ✓（参考的正则就是允许的 ✓）
    let after = &after_colon[q + 1..];
    let end = after.find('"')?;
    let code = &after[..end];
    if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
        Some(code.to_string())
    } else {
        None
    }
}

// ─────────────────────────── ChatGPT（四档：能用的那一边不一样）───────────────────────────

/// ChatGPT 要探的三个地址 ✓（照参考实现 ✓）。
pub const CHATGPT_API: &str = "https://api.openai.com/compliance/cookie_requirements";
pub const CHATGPT_IOS: &str = "https://ios.chat.openai.com/";
pub const CHATGPT_FAVICON: &str = "https://chatgpt.com/favicon.ico";

/// ⭐ **favicon 那次请求要带的那套头** ✓✓ —— 照参考实现**逐行抄** ✓（它是 `curl -H '…'` 一整组 ✓）：
/// `accept`（图片那串 ✓）· `accept-language` ✓ · **`authorization: Bearer null`** ✓ ·
/// `content-type` ✓ · `origin`/`referer` ✓ · `sec-ch-ua*` ✓ · `sec-fetch-*` ✓ · **Edge 的 UA** ✓。
/// ⚠️ 为什么值得抄 ✓：favicon 的 **403** 是"API 那边不支持这个国家"的**第二重确认** ✓✗
///（`chatgpt_verdict` 里那个 `&& favicon_status == 403` ✓）——
/// 而我们此前**一个头都没带** ✗ ⇒ Cloudflare 多半直接给别的码 ✓ ⇒ 那两档**结构性地到不了** ✓✗。
/// ⚠️ 两处**刻意不抄** ✗：① 参考里还有一个 `authority:` ✓ —— 那是 HTTP/2 的伪头 ✓，
/// 在 HTTP/1.1 里没有意义 ✓（我们自己的 `Host:` 是对的 ✓）；
/// ② 参考里 `accept` 出现了**两次** ✓（图片那串 + `*/*` ✓）—— 只抄前一个 ✓（够用 ✓ 且少一个头 ✓）。
pub const CHATGPT_FAVICON_HEADERS: &str = "accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8\r\n\
accept-language: zh-CN,zh;q=0.9\r\n\
authorization: Bearer null\r\n\
content-type: application/json\r\n\
origin: https://chatgpt.com\r\n\
referer: https://chatgpt.com/\r\n\
sec-ch-ua: \"Microsoft Edge\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\"\r\n\
sec-ch-ua-mobile: ?0\r\n\
sec-ch-ua-platform: \"Windows\"\r\n\
sec-fetch-dest: empty\r\n\
sec-fetch-mode: cors\r\n\
sec-fetch-site: same-site\r\n\
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0";
pub const CHATGPT_TRACE: &str = "https://chat.openai.com/cdn-cgi/trace";

/// ChatGPT 的判据 ✓✓ —— 纯函数 ✓，输入是**两段响应 + favicon 的状态码** ✓。
///
/// 参考实现的做法 ✓（逐行读出来的 ✓）：
/// - `api…` 的响应里出现 `unsupported_country` ⇒ API 那边**不支持这个国家** ✓；
///   ⚠️ 而参考**还要再看一眼** `chatgpt.com/favicon.ico` 是不是 **403** ✓✓ ——
///   只有 403 才认定前者有效 ✓（那一层是**二次确认** ✓：单凭一个字符串会误判 ✓✗）；
/// - `ios.chat.openai.com/` 的响应里出现 `VPN` ⇒ iOS 那边把这个地址当成 VPN ✓；
/// - 两者都"没问题" ⇒ **解锁** ✓；都有问题 ⇒ **未解锁** ✓；
/// - ⚠️ **只有 iOS 有问题** ⇒ **`web`** ✓✓（"网页能用、App 不行" ✓）；
///   **只有 API 有问题** ⇒ **`app`** ✓✓（反过来 ✓）—— 这两档**既不是解锁也不是未解锁** ✗
///   ⇒ 合并任何一边都是丢信息 ✓（用户定的"甲" ✓）。
///
/// ⚠️ **地区**由 [`chatgpt_region`] 从 trace 里取 ✓（**不在这条判据里** ✓ ——
/// 那一份是另一次请求 ✓，它的成败不该影响"能不能用"这个结论 ✓✓）。
pub fn chatgpt_verdict(api_body: &str, ios_body: &str, favicon_status: u16) -> Verdict {
    // ⚠️ 二次确认就在这一行 ✓：字符串 + favicon 403 **两者都成立**才算 API 那边不支持 ✓
    let api_bad = api_body.contains("unsupported_country") && favicon_status == 403;
    let ios_bad = ios_body.contains("VPN");
    let status = match (api_bad, ios_bad) {
        (false, false) => Status::Unlocked,
        (true, true) => Status::Blocked,
        // ⚠️ 只有 iOS 有问题 ⇒ **网页能用** ✓（API 是网页那一边 ✓）
        (false, true) => Status::Web,
        // ⚠️ 只有 API 有问题 ⇒ **App 能用** ✓
        (true, false) => Status::App,
    };
    Verdict { status, region: None }
}

/// ⚠️⚠️ **两段响应的"取回结果"怎么变成结论** ✗✗ —— 纯函数 ✓ 所以有测试 ✓。
///
/// 旧写法是 `if let (Ok(api), Ok(ios))` ✗ ⇒ **只要有一边取不到，整条都不报** ✓✗
/// ⇒ hub 那边整份覆盖 ⇒ 面板上**一片空白** ✓ —— 用户那张图上 ChatGPT 就是空的 ✓✓。
/// ⭐ 而"有一边没读到"和"两边都没读到"**不是一回事** ✗：
///   · **只有一边读到** ⇒ 说不出"解锁 / 仅网页 / 仅 App"里是哪一档 ✓ ⇒ **如实说"没读明白"** ✓；
///   · **两边都没读到** ⇒ 那是**网络故障** ✓，不是结论 ⇒ **不报** ✓（与 Netflix/TikTok 同一条规矩 ✓）。
///
/// ⚠️ 为什么把 favicon 当**参数**而不是在里面 await ✗：这一条要是纯的 ✓ 才测得了 ✓
///（判据能测，是这个仓最值钱的那条规矩 ✓）。
fn chatgpt_from_results(api: Option<&str>, ios: Option<&str>, favicon_status: u16) -> Option<Verdict> {
    match (api, ios) {
        (Some(a), Some(b)) => Some(chatgpt_verdict(a, b, favicon_status)),
        (Some(_), None) | (None, Some(_)) => Some(Verdict { status: Status::Unknown, region: None }),
        (None, None) => None,
    }
}

/// 从 Cloudflare 的 trace 里取地区 ✓（`loc=XX` ✓ —— 参考实现就是这么取的 ✓）。
/// 形状检查照旧 ✓：**必须两位大写字母** ✓（`loc=` 后面可能还有别的东西 ✓✗）。
pub fn chatgpt_region(trace: &str) -> Option<String> {
    let i = trace.find("loc=")? + 4;
    let rest = &trace[i..];
    let end = rest.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(rest.len());
    let code = &rest[..end];
    if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
        Some(code.to_string())
    } else {
        None
    }
}

// ─────────────────────────────── Reddit（结论就是状态码）───────────────────────────────

/// Reddit 要取的地址 ✓（照参考实现 ✓ —— 完整那一条 ✓）。
pub const REDDIT_URL: &str = "https://www.reddit.com/svc/shreddit/reddit-chat";

/// Reddit 的判据 ✓✓ —— 纯函数 ✓，输入是**状态码与正文** ✓。
///
/// 参考实现就是按状态码判的 ✓（它用 `--write-out '%{http_code}'` 取那个码 ✓）：
/// - **200 ⇒ 解锁** ✓，地区从正文里的 `country="XX"` 取 ✓；
/// - **403 ⇒ 未解锁** ✓✓ —— ⚠️ 这是 Reddit 表达"这个区不行"的方式 ✓，
///   所以它**必须被当成结论** ✓✗（若把 403 当"取页失败" ✓，用户看到的是"还没测过" ✓✗，
///   而真相是"**被拒了**" ✓ —— 两件事 ✓）；
/// - **其它码 ⇒ 不猜** ✓（`Unknown` ✓）：那既不是"能用"也不是"被拒" ✓
///   （例如 5xx ✓ —— 服务器自己的问题 ✓）。
///
/// ⚠️ 而这正是 [`fetch_status`] 存在的原因 ✗：普通 [`fetch`] 遇到非 200 就报错 ✓，
/// 那会把 403 这个**明确的结论**变成"没连上" ✓✗。
pub fn reddit_verdict(status: u16, body: &str) -> Verdict {
    match status {
        // ⚠️ 200 也要过地板 ✗：一个 200 的小页面**不是** Reddit 的页面 ✓
        //（实测正常那页是 **306 KB** ✓），把它读成"解锁"就是同一类错值 ✓。
        200 if looks_like_a_real_page(body) => {
            Verdict { status: Status::Unlocked, region: reddit_region(body) }
        }
        // ⚠️ **403 那条语义一个字没动** ✓ —— 参考与我们都判"屏蔽" ✓，用户那张图上也一致 ✓。
        403 => Verdict { status: Status::Blocked, region: None },
        _ => Verdict { status: Status::Unknown, region: None },
    }
}

/// 从正文里取地区 ✓（`country="XX"` ✓，照参考实现 ✓）——
/// 形状检查照旧 ✓：**必须两位大写字母** ✓（否则别的 `country="…"` 会被当地区 ✓✗）。
pub fn reddit_region(body: &str) -> Option<String> {
    // 取第一个有效的：参考是 grep -oE 全部匹配，再 grep -m1 .（第一个非空）。
    // 形状检查照旧且更严：必须两位大写（参考只要求非空；这一条是刻意收紧的）。
    // 差别只在 第一处是空、第二处有值 时：参考拿第二个，我们先前直接放弃。
    const KEY: &str = "country=\"";
    let mut from = 0usize;
    while let Some(i) = body[from..].find(KEY) {
        let start = from + i + KEY.len();
        from = start;
        let Some(end) = body[start..].find('"') else { continue };
        let code = &body[start..start + end];
        if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
            return Some(code.to_string());
        }
    }
    None
}

// ─────────────────────────────── TikTok（三档 + 机器人拦截）───────────────────────────────

/// TikTok 要取的两个地址 ✓（照参考实现 ✓）：主站 ✓ 与"被拦截时换的那个" ✓。
pub const TIKTOK_MAIN: &str = "https://www.tiktok.com/";
pub const TIKTOK_FALLBACK: &str = "https://www.tiktok.com/explore";

/// 这一页是不是**机器人拦截页** ✓✓ —— 参考实现判据的原话是 `Please wait...` ✓。
///
/// ⚠️ 它**不是**"未解锁" ✗✗：拦截页说明**我们没读到内容** ✓ ⇒ 那一路要重试或如实说"没读到" ✓。
/// 把拦截当成"被墙"是这一块最容易犯的错 ✓（而且它的结论**看起来很合理** ✓✗）。
pub fn is_bot_check(page: &str) -> bool {
    page.contains("Please wait...")
}

/// 从页面里取地区 ✓（`"region":"XX"` ✓）。
/// ⚠️ 形状检查照 Netflix 那条的规矩 ✓：**必须两位大写字母** ✓ ——
/// 否则页面上任何 `"region":"…"` 都会被当地区 ✓✗（例如语言码 ✓、别的字段 ✓）。
pub fn tiktok_region(page: &str) -> Option<String> {
    // ⚠️ 取**最后一处** ✓✓（参考：`grep '"region":' | sed 's/.*"region"//' | cut -f2 -d'"'` ✓ ——
    // 那个 `.*` 是贪婪的 ✓，所以它拿到的是**最后一处** ✓）。与 YouTube 那条同一规矩 ✓。
    const KEY: &str = "\"region\":\"";
    let mut found: Option<String> = None;
    let mut from = 0usize;
    while let Some(i) = page[from..].find(KEY) {
        let start = from + i + KEY.len();
        from = start;
        let Some(end) = page[start..].find('"') else { continue };
        let code = &page[start..start + end];
        // 形状检查照旧 ✓：必须两位大写 ✓（否则语言码/别的字段都会被当地区 ✓✗）
        found = if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
            Some(code.to_string())
        } else {
            None
        };
    }
    found
}

/// TikTok 的判据 ✓✓ —— 纯函数 ✓，输入是**两次请求**的结果 ✓（主站 ✓ 与"带长 Accept 的那次" ✓）。
///
/// 参考实现的三档 ✓（逐行读出来的 ✓）：
/// - **主站给了地区** ⇒ **解锁** ✓（地区就是它 ✓）；
/// - 主站**没给**地区、而**第二次**给了 ⇒ **机房** ✓✓（`Idc` ✓ —— "能解，但被识别成机房" ✓）；
/// - 两次都没有 ⇒ **未解锁** ✓。
///
/// ⚠️ 而**拦截页**另走一路 ✗：它说明"没读到" ✓ ⇒ `Unknown` ✓，**不是**"未解锁" ✓✗
///（重试与否交给调用方 ✓ —— 那半段要发请求，不可单测 ✓）。
pub fn tiktok_verdict(main: &str, second: &str) -> Verdict {
    if let Some(r) = tiktok_region(main) {
        return Verdict { status: Status::Unlocked, region: Some(r) };
    }
    if is_bot_check(main) {
        return Verdict { status: Status::Unknown, region: None };
    }
    if let Some(r) = tiktok_region(second) {
        return Verdict { status: Status::Idc, region: Some(r) };
    }
    // ⚠️⚠️ 兜底**不是** `blocked` ✗ —— 参考实现这一档是 **Failed（失败）** ✓，
    // 而它唯一给 `Block` 的分支是**死代码** ✓（`curl` 的错误走 stderr ✓，`$( )` 抓不到 ✓，
    // 审计里已逐行复核 ✓）⇒ ⭐ **TikTok 不该有"被墙"这一档** ✓。
    // 旧写法把"我什么都没读到"说成了"这个区不行" ✓✗ —— 与 AmazonPV 同一个毛病 ✓。
    Verdict { status: Status::Unknown, region: None }
}

/// TikTok 那两个要取的自制剧页面 ✓（判据用的是它们 ✓ —— 见 [`netflix_verdict`] ✓）。
pub const NETFLIX_PAGES: [&str; 2] =
    ["https://www.netflix.com/title/81280792", "https://www.netflix.com/title/70143836"];

// ─────────────────────────── 探一轮（所有服务；一个失败不影响其它）───────────────────────────

/// 第二次请求用的 Accept ✓（照参考实现 ✓ —— 它就是"机房"那一档的分水岭 ✓）。
/// ⚠️ 参考里那行被截断了 ✓，我只看到 `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif…` ✓
/// ⇒ 这里用一个**浏览器样**的 Accept ✓（这是**未完全核实**的一处 ✗ —— 记在这里 ✓，
///   若 TikTok 那一档老是不出现 ✓，第一个该看的就是这个常量 ✓）。
pub const TIKTOK_BROWSER_ACCEPT: &str =
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

/// 探**所有**服务 ✓ 并合并成一份报文 ✓。
///
/// ⚠️ **一个服务失败不影响其它** ✓✓（各自独立地报或沉默 ✓）——
/// 用"任一失败就整体不报"会让一次网络抖动抹掉别的服务的结论 ✓✗。
/// ⚠️ 而**全都失败 ⇒ `None`** ✓（**不报空报文** ✗：那会让面板看起来"探测过了、什么都没有" ✓✗）。
pub async fn run() -> Option<serde_json::Value> {
    let mut out = serde_json::Map::new();

    // Netflix ✓：两页**并行**取 ✓（串行是白等一倍 ✓）；任一失败 ⇒ 这个服务这次不报 ✓。
    let (a, b) = tokio::join!(
        fetch_with_capped(NETFLIX_PAGES[0], "", NETFLIX_MAX_BYTES, &|_| false),
        fetch_with_capped(NETFLIX_PAGES[1], "", NETFLIX_MAX_BYTES, &|_| false)
    );
    // ⚠️ 走**带上限**那条路 ✓（两个 title 页面都在 2 MB 以上 ✓，默认 512 KB 读不全 ✓）。
    if let (Ok(pa), Ok(pb)) = (a, b) {
        merge(&mut out, verdict_json("netflix", &netflix_verdict(&pa, &pb)));
    }

    // TikTok ✓：主站 ⇒ 被拦截就换 fallback 再取一次 ✓ ⇒ 需要时才发第二次（带浏览器 Accept ✓）。
    if let Ok(main) = fetch(TIKTOK_MAIN).await {
        let main = if is_bot_check(&main) {
            // 换一个地址再试一次 ✓；**再失败就用原来那份** ✓（它仍是拦截页 ⇒ 判据给 `Unknown` ✓✓，
            // 也就是"没读到" ✓ —— 正是实话 ✓）。
            fetch(TIKTOK_FALLBACK).await.unwrap_or(main)
        } else {
            main
        };
        // ⚠️ 第二次**只在主站没给出地区时才发** ✗✓ —— 主站给了地区就已经是结论了 ✓
        //（解锁 ✓）⇒ 省掉一次对外请求 ✓✓（每个请求都是可被观察的流量 ✓）。
        // ⚠️⚠️ **被拦截也要发第二次** ✗✗ —— 我先前这里多写了一道 `!is_bot_check(&main)` ✓，
        // 于是"主站返回拦截页 ⇒ 干脆不发" ✓✗ —— 而参考实现**只在第一次**拿拦截页当门 ✓
        //（`[[ $Ftmpresult == *"Please wait..."* ]] && … /explore` ✓），**第二次照样发** ✓。
        // ⇒ ⭐ 那道门恰好砍掉了**能拿到 `idc` 的那条路** ✓（审计早就指出过 ✓）。
        // ⚠️ 而"主站已经给出地区 ⇒ 不再发"这条**留着** ✗ —— 那是刻意的 ✓：
        // 那时候结论已经是"解锁 + 地区" ✓，第二次不可能给出更多 ✓，而每个请求都是可被观察的流量 ✓。
        let second = if tiktok_region(&main).is_none() {
            fetch_with(TIKTOK_MAIN, TIKTOK_BROWSER_ACCEPT).await.unwrap_or_default()
        } else {
            String::new()
        };
        merge(&mut out, verdict_json("tiktok", &tiktok_verdict(&main, &second)));
    }

    // Reddit ✓：⚠️ 它的结论**就是状态码** ✗（403 ⇒ 未解锁 ✓ / 200 ⇒ 解锁 ✓）——
    // 所以这里用 [`fetch_status`] ✓（**不是** `fetch` ✓：后者遇非 200 直接报错 ✓，
    // 那会把 403 这个**明确的结论**变成"没连上" ✓✗）。
    // ⚠️ 而**连不上**（Err ✓）仍然什么都不报 ✓ —— 那才是真的"没读到" ✓✓。
    if let Ok((status, body)) = fetch_status(REDDIT_URL, "").await {
        merge(&mut out, verdict_json("reddit", &reddit_verdict(status, &body)));
    }

    // ChatGPT ✓：两段响应的**内容** + favicon 的**状态码**（二次确认 ✓），
    // 地区来自**另一次**请求（trace ✓）—— ⚠️ 它取不到**不影响**"能不能用"这个结论 ✓✓。
    let (api, ios) = tokio::join!(fetch(CHATGPT_API), fetch(CHATGPT_IOS));
    let (api, ios) = (api.ok(), ios.ok());
    // ⚠️ favicon 与 trace 只在**两边都读到**时才有意义 ✓（favicon 是那次判定的二次确认 ✓）；
    // 只有一边读到的话结论本来就是"没读明白" ✓ ⇒ 不必再花两次请求 ✓。
    let both = api.is_some() && ios.is_some();
    let favicon = if both {
        // favicon 只**看状态码** ✓ ⇒ 用 `fetch_status` ✓（非 200 是它的正常取值之一 ✓，不是失败 ✓）
        fetch_status(CHATGPT_FAVICON, CHATGPT_FAVICON_HEADERS).await.map(|(s, _)| s).unwrap_or(0)
    } else {
        0
    };
    if let Some(mut v) = chatgpt_from_results(api.as_deref(), ios.as_deref(), favicon) {
        // 地区来自**另一次**请求（trace ✓）—— ⚠️ 它取不到**不影响**"能不能用"这个结论 ✓✓。
        if both {
            if let Ok(trace) = fetch(CHATGPT_TRACE).await {
                v.region = chatgpt_region(&trace);
            }
        }
        merge(&mut out, verdict_json("chatgpt", &v));
    }

    // AmazonPV ✓：最干净的一个 ✓ —— 一个 GET、一个字段、三个既有状态 ✓✓。
    if let Ok(body) = fetch(AMAZONPV_URL).await {
        merge(&mut out, verdict_json("amazonpv", &amazonpv_verdict(&body)));
    }

    // YouTube ✓：要带那两个头 ✓（否则页面上那几个字符串对不上 ✓✗）。
    // ⚠️ 走**带上限与停手条件**的那条路 ✓（它的标记在 813 KB 处 ✓，默认 512 KB 读不到 ✓）。
    if let Ok(page) =
        fetch_page_capped(YOUTUBE_URL, YOUTUBE_HEADERS, YOUTUBE_MAX_BYTES, &youtube_decided).await
    {
        // ⭐ **先判"我们最后落在哪"** ✓✓ —— 中国版只可能由它得出 ✓（正文不再参与这一档 ✓）。
        let v = if youtube_is_cn_final(&page.final_url) {
            Verdict { status: Status::Cn, region: Some("CN".into()) }
        } else {
            youtube_verdict(&page.body)
        };
        merge(&mut out, verdict_json("youtube", &v));
    }

    if out.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(out))
    }
}

/// 把一份单服务的报文并进总报文 ✓（形状是"每服务一格" ✓）。
fn merge(into: &mut serde_json::Map<String, serde_json::Value>, one: serde_json::Value) {
    if let Some(o) = one.as_object() {
        for (k, v) in o {
            into.insert(k.clone(), v.clone());
        }
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
    fetch_with(url, "").await
}

/// 同 [`fetch`] ✓，但可以多带**一个请求头** ✓ —— TikTok 的第二次请求要用它区分"机房" ✓
///（参考实现就是靠换这段 Accept 头拿到不同结果的 ✓）。
/// 同 [`fetch`] ✓，但**把最终状态码也带出来** ✓✓ —— 有些服务的结论**就是状态码** ✓
///（Reddit：**403 ⇒ 未解锁** ✓ / **200 ⇒ 解锁** ✓ —— 见它的判据 ✓）。
///
/// ⚠️ 它**不因非 200 报错** ✗（那正是它存在的理由 ✓）；只有"连不上 / 读不出来 / 跳转太多"
/// 才算失败 ✓✓ —— 这两件事必须分得开 ✓：**"对方拒绝了"是结论** ✓，**"我们没连上"不是** ✓。
///
/// ⚠️ **跳转照样跟随** ✓（与 `fetch` 同一套 ✓）：不跟的话读到的是跳转页 ✓，
/// 而它的内容看起来也像正常页面 ✓✗ ⇒ 状态码与正文都会被带偏 ✓。
pub async fn fetch_status(url: &str, extra_header: &str) -> anyhow::Result<(u16, String)> {
    // ⚠️ 默认**一字不变** ✓：全局上限 ✓、从不提前收手 ✓。
    fetch_status_capped(url, extra_header, MAX_BYTES, &|_| false).await
}

/// 同 [`fetch_status`] ✓，但可以指定**这次最多读多少** ✓ 以及**什么时候算够了** ✓✓ ——
/// 只给 YouTube 用 ✓（它的标记在 813 KB 处 ✓，全局上限读不到 ✓）。
/// ⚠️ 那个 trait object 必须 **`Send + Sync`** ✗：`run()` 的 future 要被 `tokio::spawn` ✓，
/// 不带上它编译就过不去 ✓（我第一版正是漏了这两个 ✓，编译器当场拦下 ✓）。
/// 一次取页的结果 ✓✓ —— ⚠️ **最终地址**必须一起带出来 ✗：
/// 有些判据的凭据**不是正文，而是"我们最后落在哪个主机"** ✓✓（YouTube 的"中国版"就是 ✓）。
/// ⚠️ 从前这里只有状态码与正文 ✓ ⇒ 调用方**看不出**自己是不是被跳走了 ✓✗ ——
/// 于是只能去正文里找痕迹 ✓（`www.google.cn` ✓），而那是个**误报的来源** ✗
/// （Google 自己的页面 / hreflang 链接 / 缓存片段里都有它 ✓）。
pub struct Page {
    pub status: u16,
    pub body: String,
    pub final_url: String,
}

pub async fn fetch_page_capped(
    url: &str,
    extra_header: &str,
    cap: usize,
    done: &(dyn Fn(&str) -> bool + Send + Sync),
) -> anyhow::Result<Page> {
    const MAX_REDIRECTS: u8 = 3;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let (status, headers_end, body) =
            tokio::time::timeout(TIMEOUT, get_once(&current, extra_header, cap, done)).await??;
        if (300..400).contains(&status) {
            match header(&body[..headers_end.min(body.len())], "location") {
                // ⚠️ 相对跳转**要认** ✓（`resolve_location` 会拼成绝对 ✓）；
                // 只有"解析不出来"或"会掉到明文"才拒绝 ✓ —— 那条安全规矩不动 ✓。
                Some(loc) => match resolve_location(&current, &loc) {
                    Some(next) => current = next,
                    None => anyhow::bail!("refusing a non-https redirect from {current}: {loc}"),
                },
                // 跳转但没给目标 ⇒ 就当这是最终响应 ✓（状态码本身仍是信息 ✓）
                None => return Ok(Page { status, body, final_url: current }),
            }
            continue;
        }
        // ⚠️ 交给判据的**只留正文** ✗（见 `body_of` 的说明：头部里有假阳性）。
        // 跳转判定用的是上面切出来的头部，不受这里影响。
        let page_body = body_of(&body).to_string();
        note(&current, status, &page_body);
        return Ok(Page { status, body: page_body, final_url: current });
    }
    anyhow::bail!("too many redirects starting at {url}")
}

/// 同 [`fetch_page_capped`] ✓，但只交出**状态码与正文** ✓（多数调用者只要这两样 ✓）。
pub async fn fetch_status_capped(
    url: &str,
    extra_header: &str,
    cap: usize,
    done: &(dyn Fn(&str) -> bool + Send + Sync),
) -> anyhow::Result<(u16, String)> {
    let p = fetch_page_capped(url, extra_header, cap, done).await?;
    Ok((p.status, p.body))
}

pub async fn fetch_with(url: &str, extra_header: &str) -> anyhow::Result<String> {
    fetch_with_capped(url, extra_header, MAX_BYTES, &|_| false).await
}

/// 同 [`fetch_with`] ✓，但可以指定**上限**与**停手条件** ✓ —— 见 [`fetch_status_capped`] ✓。
pub async fn fetch_with_capped(
    url: &str,
    extra_header: &str,
    cap: usize,
    done: &(dyn Fn(&str) -> bool + Send + Sync),
) -> anyhow::Result<String> {
    // ⚠️ 行为与从前**一字不变** ✓：非 200 一律算失败 ✓（Netflix 与 TikTok 的判据就是这样假设的 ✓）。
    // 需要看状态码的服务走 [`fetch_status`] ✓ —— 两条路各取所需 ✓，谁也不改变谁 ✓。
    let (status, body) = fetch_status_capped(url, extra_header, cap, done).await?;
    if status != 200 {
        anyhow::bail!("{url} answered HTTP {status}");
    }
    Ok(body)
}

/// 发一次请求并读回（**最多** `MAX_BYTES` ✓）。返回 `(状态码, 头部结束位置, 全文)`。
/// ⚠️ 与 `fetch` 拆开只是为了让上面那段跳转逻辑**读起来是一件事** ✓。
/// 诊断收集器（`--probe-once` 用）。
///
/// 为什么要它：判断、解分块、窗口、请求头、cookie 都验过之后，仍然有一台机器报
/// "没读明白"。剩下能解释的只有"它读到的页面与 curl 读到的不一样"，而这件事
/// 从外面看不见。所以让取页层自己把每一份响应的事实记下来：
/// URL、状态码、正文长度、以及几个标记各出现几次。
/// 于是"读到 94 万字节但 ad-free=0"（页面不同）与"只读到 12 万字节"（连接被关掉）
/// 一眼就能分开，而这两条路的修法完全不同。
///
/// 平时零成本：一个原子布尔，关着的时候连锁都不碰。放在取页那一层而不是逐个服务里，
/// 是因为那样不会漏（两页 Netflix、favicon、TikTok 的第二次请求都在这里经过）。
static DIAG_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static DIAG_LINES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
/// 落盘目录（诊断时可选）。有些问题只有看见正文才能定性——
/// 比如"服务端给我们的是一页 33 KB 的东西，而 curl 拿到的是 950 KB 的正常页"，
/// 那一页是什么，光看长度猜不出来。
static DIAG_DUMP: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
static DIAG_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 打开诊断并清空上一次的。给了目录就顺便把每份正文落盘。
pub fn start_diagnostics(dump_dir: Option<String>) {
    DIAG_LINES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    *DIAG_DUMP.lock().unwrap_or_else(|e| e.into_inner()) = dump_dir;
    DIAG_SEQ.store(0, std::sync::atomic::Ordering::Relaxed);
    DIAG_ON.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// 取走这一轮记下的，并关上诊断。
pub fn take_diagnostics() -> Vec<String> {
    DIAG_ON.store(false, std::sync::atomic::Ordering::Relaxed);
    std::mem::take(&mut *DIAG_LINES.lock().unwrap_or_else(|e| e.into_inner()))
}

/// 诊断里问的那几个标记，覆盖六个服务。多问几个没有代价（一轮六次字符串扫描）。
const DIAG_NEEDLES: [&str; 8] = [
    "ad-free",
    "contentRegion",
    "Oh no!",
    "currentTerritory",
    "\"region\":\"",
    "unsupported_country",
    "VPN",
    "Please wait...",
];

/// 一份响应的事实，一行。纯函数，所以它有测试。
pub fn diag_line(url: &str, status: u16, body: &str) -> String {
    let mut out = format!("{url} status={status} bytes={}", body.len());
    for needle in DIAG_NEEDLES {
        let n = body.matches(needle).count();
        if n > 0 {
            out.push_str(&format!(" {}={n}", needle));
        }
    }
    out
}

/// 记一份响应（只在诊断开着时）。
fn note(url: &str, status: u16, body: &str) {
    if !DIAG_ON.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let line = diag_line(url, status, body);
    DIAG_LINES.lock().unwrap_or_else(|e| e.into_inner()).push(line.clone());
    // 给了目录就落盘。文件名带序号，于是顺序与上面那几行一一对应。
    let dump = DIAG_DUMP.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(dir) = dump {
        let n = DIAG_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::path::Path::new(&dir).join(format!("{n:02}.txt"));
        let header = format!("# {line}\n\n");
        let _ = std::fs::write(&path, format!("{header}{body}"));
    }
}

/// **只取正文**：头部之后的全部内容。纯函数，所以它有测试。
///
/// ⚠️⚠️ 这个函数是 2026-10-15 那次事故的直接产物：YouTube 的响应头里有一条
/// `connection-allowlist-report-only`，那串名单**包含 `https://www.google.cn`**。
/// 而"读够了就停"的判据当时是拿**整份响应**（含头部）去找标记的，于是第一批字节就命中，
/// 读到 33,138 字节就收手，真正的标记在 818 KB 处永远读不到——面板上就是"没读明白"。
/// ⇒ 判据是**关于正文**的，就必须只看正文。
fn body_of(text: &str) -> &str {
    match text.find("\r\n\r\n") {
        Some(i) => &text[i + 4..],
        // 没有分界（被截断，或压根不是 HTTP 响应）⇒ 整份都算正文。
        // 宁可多给一点，也不要因为找不到分界就交出空串——那会把判据饿死。
        None => text,
    }
}

/// 造一条 HTTP/1.1 请求 ✓✓（纯函数 ✓ —— 所以"发了几个 `Accept`"这种事**测得了** ✓）。
///
/// ⚠️⚠️ **`User-Agent` 与 `Accept` 默认给，但能被 extra 覆盖** ✗✗ ——
/// 从前那两行是**硬写**的 ✓，而 extra 是**追加**上去的 ✓✗ ⇒ 只要 extra 里也有一个 `Accept`
/// ✓，发出去就是**两个** ✓（参考实现给的是 `-H "Accept: …"` ✓，那会**替换** curl 的默认头 ✓；
/// 我们却是叠加 ✓）。用户要的 TikTok 那一次正是这种情形 ✓。
/// ⚠️ `Host` **不许被覆盖** ✗：它必须与我们要连的主机一致 ✓（extra 里的 `authority:` 是 HTTP/2
/// 的伪头 ✓，在 HTTP/1.1 里没有意义 ✓ ⇒ 忽略它 ✓）。
fn build_request(path: &str, authority: &str, extra_header: &str) -> String {
    let extra = extra_header.trim();
    // 这两行由本函数自己写 ⇒ extra 里的一律丢掉，否则会发出两份。
    // 是那条测试抓住的（它先报 UA 数不对，接着报 Host 被夹带）。
    let extra: String = extra
        .lines()
        .map(str::trim)
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            !l.is_empty() && !low.starts_with("host:") && !low.starts_with("connection:")
        })
        .map(|l| format!("{l}\r\n"))
        .collect();
    let has =
        |name: &str| extra.lines().any(|l| l.trim().to_ascii_lowercase().starts_with(&format!("{name}:")));
    let ua = if has("user-agent") { "" } else { "User-Agent: monitor-agent\r\n" };
    let accept = if has("accept") { "" } else { "Accept: */*\r\n" };
    let extra_line = extra.as_str();
    format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n{ua}{accept}{extra_line}Connection: close\r\n\r\n")
}

async fn get_once(
    url: &str,
    extra_header: &str,
    cap: usize,
    done: &(dyn Fn(&str) -> bool + Send + Sync),
) -> anyhow::Result<(u16, usize, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    // ⚠️ 自定义头**只在给了的时候**才加 ✓ —— 空字符串不加，免得写出一个空头行 ✓✗
    //（空头行会被某些服务器当成请求结束 ✓，那会让"取页成功但没有内容" ✓✗ —— 安静的错 ✓）。
    let req = build_request(path, authority, extra_header);
    tls.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut checked = 0usize;
    loop {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        // ⚠️ **先解 chunked、再判"够了没有"** ✗✓ —— 否则判据看到的是带分块框架的原始字节 ✓，
        // 标记跨块边界时会被框架打断 ✓（那正是"状态照旧、地区静默消失"的来源 ✓）。
        // ⚠️ 每 32 KB 才检查一次 ✓：每次检查都要把已有的正文重解一遍 ✓，
        // 每读一小块就查一次会变成平方级 ✓（8 KB 一块 ⇒ 100 多次重解 ✓）。
        if buf.len() - checked >= 32 * 1024 {
            checked = buf.len();
            if done(body_of(&assemble(&buf))) {
                break;
            }
        }
        if buf.len() >= cap {
            buf.truncate(cap);
            break;
        }
    }
    let text = assemble(&buf);
    let (status, headers_end) = parse_status_and_headers(&text)?;
    Ok((status, headers_end, text))
}

/// 把**原始响应字节**变成"头部 + 正文"文本 ✓✓。
/// ⚠️ 若对方用了 `Transfer-Encoding: chunked`，**这里把分块框架剥掉** ✗ ——
/// 我们此前是**裸读** ✓ ⇒ 正文里会混着 `1a2b\r\n` 这类框架 ✓
/// ⇒ **标记只要跨块边界就会断** ✓，而"状态照旧、地区静默消失"正是本仓最怕的那类错 ✓。
///
/// ⚠️⚠️ **但别把这条说成 YouTube 那个 bug 的原因** ✗✗ —— 我一度这么写过，是错的 ✓。
/// 2026-10-13 我自己用代理实测（两次，一次 curl 默认头、一次 agent 自己那套头 ✓）：
/// 那个响应**都没有** `transfer-encoding` ✓（是 Content-Length ✓）
/// ⇒ 那一次**唯一的拦路虎就是 512 KB 上限** ✓✗。
/// 保留剥框架 ✓ 是因为别的服务/别的时刻确实会分块 ✓（审计里 Reddit 那一条实测就是 ✓），
/// 而不是因为它能治 YouTube 这一次 ✓ —— 写清楚，免得下一个人把因果搞反 ✓。
/// ⚠️ 只动正文 ✓：头部原样保留 ✓（跳转、状态码都还要用 ✓）。
fn assemble(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let Some(headers_end) = text.find("\r\n\r\n").map(|i| i + 4) else {
        return text.into_owned();
    };
    let head = &text[..headers_end];
    if !head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return text.into_owned();
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(head);
    out.push_str(&dechunk(&text[headers_end..]));
    out
}

/// 剥掉 HTTP/1.1 的分块框架 ✓（纯函数 ✓ —— 所以它有测试 ✓✓）。
/// ⚠️ 三件必须处理的事 ✗：
///   ① 块大小是**十六进制** ✓，而且**可以带 `;扩展`** ✓；
///   ② 最后一块是 `0` ✓，其后是 trailer ✓ —— 见到就收手 ✓；
///   ③ ⚠️ **截断**（我们读到一半就停 ✓）⇒ **把手上已经拿到的交出去** ✓✗，
///      绝不因为"不完整"就整条丢掉 ✓（丢掉等于把读到的正文扔了 ✓）。
/// ⚠️ 若**第一行就不是块大小** ⇒ **原样返回** ✓ —— 宁可不剥，也不吃掉正文 ✓。
fn dechunk(body: &str) -> String {
    // ⚠️⚠️ **全程按字节切** ✗✗ —— 块大小是**字节数**，而 `&str` 按下标切要求落在字符边界上。
    // 这不只是理论风险：`assemble` 先做了一次 `from_utf8_lossy`，非法字节被替换成三字节的
    // U+FFFD ⇒ **偏移整体漂移**，服务端给的 size 于是完全可能落在某个多字节字符中间。
    // 旧实现在那里 `&rest[..size]` ⇒ panic，而 release 是 `panic = "abort"` ⇒ **整个 agent 被
    // abort**；更糟的是 `remember()` 还没执行，重启后 `due()` 仍为真 ⇒ 每 5 秒重探、再 abort
    // （`Restart=always`）。一次分块响应就能把一台机器变成崩溃循环。
    //
    // 与前面几条同样的三条规矩：块大小是十六进制且可带 `;扩展`、见到 0 收手、
    // **截断时把读到的交出去**、第一行不是块大小就原样返回。
    let bytes = body.as_bytes();
    let crlf = |b: &[u8]| b.windows(2).position(|w| w == b"\r\n");
    let size_of = |line: &[u8]| -> Option<usize> {
        std::str::from_utf8(line)
            .ok()
            .and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok())
    };
    match crlf(bytes) {
        Some(eol) if size_of(&bytes[..eol]).is_some() => {}
        _ => return body.to_string(),
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some(eol) = crlf(rest) {
        let Some(size) = size_of(&rest[..eol]) else {
            return body.to_string();
        };
        rest = &rest[eol + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            out.extend_from_slice(rest);
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        match rest.strip_prefix(b"\r\n".as_slice()) {
            Some(next) => rest = next,
            None => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

/// 把响应里的 `Location` 解析成**绝对 https URL** ✓✓（纯函数 ✓ —— 所以它有测试 ✓）。
///
/// ⚠️⚠️ 我们此前只接受 `starts_with("https://")` ✗✗ ⇒ **相对跳转被当成错误** ✓
/// ⇒ 整次取页失败 ✓。实测（2026-10-13 ✓）：`https://www.primevideo.com` 的 302
/// 给的就是**相对路径** `/offers/nonprimehomepage?ref_=...` ✓ ⇒ **PrimeVideo 取不到页** ✓✗。
/// ⚠️ 而相对跳转是 RFC 允许、且**很常见**的 ✓，不是异常 ✓。
///
/// ⚠️ 但那条安全规矩**不动** ✗：**只跟 https** ✓ —— `http://` 一律拒绝 ✓
///（明文跳转会被中间人改写 ✓，那比"取不到页"糟得多 ✓）。
/// 三种相对形式都要认 ✓：`//host/path`（协议相对 ✓）· `/path`（根相对 ✓）· `path`（路径相对 ✓）。
fn resolve_location(current: &str, loc: &str) -> Option<String> {
    let loc = loc.trim();
    if loc.starts_with("https://") {
        return Some(loc.to_string());
    }
    // ⚠️ 明文一律拒绝 ✓（含 `http://` 与协议相对里显式写 http 的情形 ✓）
    if loc.starts_with("http://") || loc.starts_with("//") && loc[2..].starts_with("http://") {
        return None;
    }
    let (scheme, rest) = current.split_once("://")?;
    if scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if loc.starts_with("//") {
        // 协议相对 ✓ ⇒ 补上当前协议 ✓
        return Some(format!("https:{loc}"));
    }
    if loc.starts_with('/') {
        return Some(format!("https://{authority}{loc}"));
    }
    if loc.is_empty() {
        return None;
    }
    // ⚠️ 其它协议（`ftp://` ✓ `mailto:` ✓ …）**一律拒绝** ✗ ——
    // 不拒的话会被当成"路径相对"拼到同一主机上 ✓✗（`https://host/ftp://a/b` ✓ 一个不存在的地址 ✓，
    // 白白多花一次跳转 ✓，而且日志里会显得像"我们跟了它" ✓）。
    if loc.contains("://") {
        return None;
    }
    // 路径相对 ✓ ⇒ 拼到当前路径**最后一个 `/` 之前** ✓
    let path = &rest[authority.len()..];
    let base = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    Some(format!("https://{authority}{base}{loc}"))
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
    /// 测试里的小助手 ✓：走**生产同一条路**（`verdict_json` + `netflix_verdict`）✓ ——
    /// ⚠️ 从前这里是一个 `netflix_report` 包装 ✓，而生产路径改走通用那条之后 ✓
    /// 它就只剩测试在用了 ✓✗ ⇒ 那个包装已删除 ✓：留着会让"测试测的路"与"线上跑的路"
    /// **不是同一条** ✓（很隐蔽的一种脱节 ✓）。
    fn nf(a: &str, b: &str) -> serde_json::Value {
        verdict_json("netflix", &netflix_verdict(&page(a), &page(b)))
    }

    use super::*;

    /// 两个页面都说看不了 ⇒ **未解锁** ✓（这是"对方明确告诉你"的那种 ✓，是结论 ✓）。
    #[test]
    fn both_pages_saying_no_means_originals_only() {
        let v = netflix_verdict(&page("<html>Oh no!</html>"), &page("<html>Oh no!</html>"));
        assert_eq!(v.status, Status::Org, "两页都说看不了 ⇒ 仅自制 ✓（能用 ✓，不是被墙 ✗）");
        assert_eq!(v.region, None, "这两页夹具里没有地区标记 ⇒ 地区就是 None ✓");
    }

    /// ⭐ **只有一页说看不了 ⇒ 不能下"未解锁"的结论** ✓✓ —— 这一条是这一块最要紧的测试 ✓：
    /// 它挡住的是"把一部剧在某区没有，说成整个 Netflix 被墙" ✓✗。
    #[test]
    fn one_page_saying_no_is_not_enough_to_call_it_blocked() {
        let v = netflix_verdict(
            &page("{\"id\":\"US\",\"countryName\":\"United States\"}"),
            &page("<html>Oh no!</html>"),
        );
        assert_eq!(v.status, Status::Unknown, "只有一页 ⇒ 没读明白 ✓，不是未解锁 ✗");
        // ⚠️ 地区**不再**跟着出来 ✓（这一条正是丁的必然结果 ✓）：
        // 参考里 blocked 与 failed 都**不给**地区 ✓ —— 给了会让人以为"还能看某些内容" ✓✗。
        // ⇒ 只有 Unlocked / Org 两档才带地区 ✓。
        assert_eq!(v.region, None, "说不清的时候不给地区 ✓（给了就成了『还能看』的暗示 ✓✗）");
    }

    /// 两页都正常 ⇒ **解锁** ✓，并取到地区 ✓。
    #[test]
    fn two_good_pages_mean_unlocked_with_a_region() {
        let a = page("{\"id\":\"JP\",\"countryName\":\"Japan\"}");
        let b = page("{\"id\":\"JP\",\"countryName\":\"Japan\"}");
        assert_eq!(netflix_verdict(&a, &b), Verdict { status: Status::Unlocked, region: Some("JP".into()) });
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
    /// ⭐⭐ **钉死那几个字面量** ✓✓ —— 这是本模块最重要的一条测试 ✗：
    /// hub 只认 `unlocked` / `blocked` / `unknown` ✓；改一个字母 ⇒ hub **整条丢掉** ✓
    /// ⇒ 面板上安静地什么都没有 ✓✗，而且**没有任何报错** ✓。
    /// ⇒ 所以这里把三个字面量**逐字**断言 ✓ —— 将来谁改这边、忘了改那边，这条会红 ✓✓。
    #[test]
    fn the_report_uses_exactly_the_words_the_hub_accepts() {
        // 解锁 ✓（带地区 ✓）
        assert_eq!(
            nf("<html>ok</html>{\"id\":\"JP\",\"countryName\":\"Japan\"}", "same"),
            serde_json::json!({"netflix": {"status": "unlocked", "region": "JP"}})
        );
        // 未解锁 ✓（两个页面都说看不了 ✓）—— 没有地区 ✓（那边没有地区可言 ✓）
        assert_eq!(nf("Oh no!", "Oh no!"), serde_json::json!({"netflix": {"status": "org"}}));
        // 没读明白 ✓ —— **照样上报** ✓（"这次没读明白"本身是有用的信息 ✓）
        assert_eq!(nf("", ""), serde_json::json!({"netflix": {"status": "unknown"}}));
        // ⚠️ 逐字对照 ✓：把三个可能被写错的形式列出来，改错就红 ✓
        for (i, want) in ["unlocked", "org", "unknown"].iter().enumerate() {
            let got = match i {
                0 => nf("ok", "ok")["netflix"]["status"].clone(),
                1 => nf("Oh no!", "Oh no!")["netflix"]["status"].clone(),
                _ => nf("", "")["netflix"]["status"].clone(),
            };
            assert_eq!(got, serde_json::json!(want), "第 {i} 种必须是 {want:?} ✓");
        }
    }

    /// 报文形状是"**每服务一格**" ✓ —— 将来加服务只多一个键 ✓，hub 与面板都不用改结构 ✓。
    #[test]
    fn the_report_is_one_key_per_service() {
        let r = nf("ok", "ok");
        let obj = r.as_object().expect("报文必须是一个对象 ✓");
        assert_eq!(obj.len(), 1, "第一期只有 netflix 一个键 ✓");
        assert!(obj.contains_key("netflix"), "键名就是服务名 ✓（hub 的白名单按它认 ✓）");
        // ⚠️ 地区**只在拿得到时**出现 ✓ —— 不给一个空的地区字段 ✓
        //（空字符串会让 hub 的形状检查挡掉它 ✓，而"没有地区"与"地区是空"是两件事 ✓）
        assert!(r["netflix"].get("region").is_none(), "拿不到地区就不给这个键 ✓");
    }
    /// ⭐ TikTok 那**三档** ✓✓ —— 第二档（机房 ✓）是最容易漏掉的 ✗：
    /// 参考实现里它是"主站没给、**第二次**给了" ✓ —— 漏掉它就会把机房机器显示成普通解锁 ✓✗。
    #[test]
    fn tiktok_keeps_unlocked_and_idc_apart() {
        let main = page("{\"region\":\"JP\"}");
        let second = page("{\"region\":\"US\"}");
        // ① 主站给了 ⇒ **解锁** ✓（地区取主站那个 ✓）
        assert_eq!(
            tiktok_verdict(&main, &second),
            Verdict { status: Status::Unlocked, region: Some("JP".into()) }
        );
        // ② 主站没给、第二次给了 ⇒ **机房** ✓✓（不是"解锁" ✗，也不是"未解锁" ✗）
        assert_eq!(
            tiktok_verdict(&page("<html>nothing</html>"), &second),
            Verdict { status: Status::Idc, region: Some("US".into()) }
        );
        // ③ 两次都没有 ⇒ **没读明白** ✓（⚠️ TikTok **没有"被墙"这一档** ✗ —— 参考的兜底是 Failed ✓）
        assert_eq!(
            tiktok_verdict(&page("<html>nope</html>"), &page("<html>nope</html>")),
            Verdict { status: Status::Unknown, region: None }
        );
    }

    /// ⚠️⚠️ **拦截页不是"未解锁"** ✗✗ —— 这一块最容易犯的错 ✓，
    /// 而且它的错值**看起来很合理** ✓（"这个区看不了" ✓）⇒ 用户会据此换机器 ✓，而问题在网络/风控上 ✓。
    #[test]
    fn a_bot_check_page_means_we_did_not_read_it() {
        let blocked_page = "<html>Please wait...</html>";
        assert!(is_bot_check(blocked_page));
        assert_eq!(
            tiktok_verdict(blocked_page, "<html>nothing</html>"),
            Verdict { status: Status::Unknown, region: None },
            "拦截 ⇒ 没读到 ✓，**不是**未解锁 ✗"
        );
        // 而"真的没有地区、也没有拦截标记" ⇒ 那才是未解锁 ✓
        assert_eq!(tiktok_verdict("<html>x</html>", "<html>y</html>").status, Status::Unknown);
    }

    /// 地区必须**两位大写字母** ✓（与 Netflix 那条同一条规矩 ✓）——
    /// 否则语言码 / 别的字段都会被当地区 ✓✗，而那种错**看起来完全正常** ✓。
    #[test]
    fn tiktok_regions_must_look_like_regions() {
        assert_eq!(tiktok_region("{\"region\":\"JP\"}").as_deref(), Some("JP"));
        assert_eq!(tiktok_region("{\"region\":\"jp\"}"), None, "小写不算 ✓");
        assert_eq!(tiktok_region("{\"region\":\"JPN\"}"), None, "三位不算 ✓");
        assert_eq!(tiktok_region("{\"region\":\"\"}"), None, "空不算 ✓");
        assert_eq!(tiktok_region("<html>nothing</html>"), None, "没有就别说 ✓");
    }

    /// 机房的报文里状态字必须是 **`idc`** ✓✓ —— 它要与 hub 的白名单**逐字一致** ✓
    /// （否则 hub 整条丢掉 ✓ ⇒ 面板安静地什么都没有 ✓✗）。
    #[test]
    fn the_idc_status_word_is_the_one_the_hub_accepts() {
        let v = tiktok_verdict("<html>x</html>", "{\"region\":\"US\"}");
        assert_eq!(
            verdict_json("tiktok", &v),
            serde_json::json!({"tiktok": {"status": "idc", "region": "US"}})
        );
    }
    /// ⭐⭐ **403 是结论，不是失败** ✓✓ —— 这是 Reddit 这一块最要紧的一条 ✗：
    /// 把 403 当"取页失败" ⇒ 面板显示"还没测过" ✓✗，而真相是"**被拒了**" ✓ ——
    /// 两件事的处置完全不同 ✓（一个要换机器 ✓，一个只要再等等 ✓）。
    #[test]
    fn reddit_reads_the_status_code_as_the_verdict() {
        // 200 ⇒ 解锁 ✓，地区从 body 取 ✓
        assert_eq!(
            reddit_verdict(200, &page("… country=\"JP\" …")),
            Verdict { status: Status::Unlocked, region: Some("JP".into()) }
        );
        // 403 ⇒ **未解锁** ✓✓（不是 Unknown ✗）
        assert_eq!(reddit_verdict(403, ""), Verdict { status: Status::Blocked, region: None });
        // 其它码 ⇒ 不猜 ✓（5xx 是服务器的问题 ✓，不是关于这个 IP 的结论 ✓）
        assert_eq!(reddit_verdict(500, "").status, Status::Unknown);
        assert_eq!(reddit_verdict(302, "").status, Status::Unknown);
        assert_eq!(reddit_verdict(0, "").status, Status::Unknown);
    }

    /// 200 但**没有地区** ⇒ 仍然算**解锁** ✓（地区拿不到就 `None` ✓ —— **不因为缺一格就改判** ✗）；
    /// 而地区形状不对 ⇒ 同样只丢地区 ✓（与 Netflix/TikTok 同一条规矩 ✓）。
    #[test]
    fn reddit_unlocked_survives_a_missing_or_odd_region() {
        assert_eq!(
            reddit_verdict(200, &page("<html>no country here</html>")),
            Verdict { status: Status::Unlocked, region: None }
        );
        for bad in ["country=\"jp\"", "country=\"JPN\"", "country=\"\""] {
            assert_eq!(
                reddit_verdict(200, &page(bad)),
                Verdict { status: Status::Unlocked, region: None },
                "{bad:?} 不该被当成地区 ✓，但状态仍是解锁 ✓"
            );
        }
    }
    /// ⭐⭐ ChatGPT 的**四档** ✓✓ —— 而其中两档是"只通一边" ✓：
    /// ⚠️ 把它们并进"解锁"会让"网页能开但 App 打不开"看起来完全正常 ✓✗ ——
    /// 而那正是运维会据以决定要不要换机器的事实之一 ✓。
    #[test]
    fn chatgpt_keeps_the_four_tiers_apart() {
        let clean_api = "{\"ok\":true}";
        let bad_api = "{\"error\":\"unsupported_country\"}";
        let clean_ios = "<html>hello</html>";
        let bad_ios = "<html>VPN detected</html>";
        // 都干净 ⇒ 解锁 ✓；都有问题（且 favicon 也是 403 ✓）⇒ 未解锁 ✓
        assert_eq!(chatgpt_verdict(clean_api, clean_ios, 200).status, Status::Unlocked);
        assert_eq!(chatgpt_verdict(bad_api, bad_ios, 403).status, Status::Blocked);
        // ⚠️ 只有 iOS 有问题 ⇒ **网页能用** ✓；只有 API 有问题 ⇒ **App 能用** ✓
        assert_eq!(chatgpt_verdict(clean_api, bad_ios, 200).status, Status::Web);
        assert_eq!(chatgpt_verdict(bad_api, clean_ios, 403).status, Status::App);
    }

    /// ⚠️⚠️ **favicon 的 403 是"二次确认"** ✓✓ —— 少了它，API 响应里**随便一个字符串**
    /// 就能把一台好机器判成"不支持这个国家" ✓✗（而那是个**看起来很合理**的错值 ✓）。
    #[test]
    fn the_api_verdict_needs_the_favicon_403_confirmation() {
        let bad_api = "unsupported_country";
        // favicon 不是 403 ⇒ **那个字符串不算数** ✓ ⇒ 仍然按"API 没问题"处理 ✓
        // ⚠️ **必须大写 `VPN`** ✗✓ —— 判据是 `contains("VPN")`（照参考实现 ✓），
        // 而 fixture 里写小写会静默落进另一档 ✓✗（我第一版就是这么写错的 ✓，被按名字跑抓到 ✓）。
        assert_eq!(chatgpt_verdict(bad_api, "<html>VPN</html>", 200).status, Status::Web);
        assert_eq!(chatgpt_verdict(bad_api, "<html>ok</html>", 404).status, Status::Unlocked);
        // 只有 403 才认 ✓
        assert_eq!(chatgpt_verdict(bad_api, "<html>ok</html>", 403).status, Status::App);
    }

    /// 地区取 Cloudflare trace 的 `loc=XX` ✓ —— 形状检查照旧 ✓（两位大写 ✓）。
    #[test]
    fn chatgpt_regions_come_from_the_trace_and_must_look_like_regions() {
        assert_eq!(chatgpt_region("ip=1.2.3.4\nloc=JP\nts=1\n").as_deref(), Some("JP"));
        assert_eq!(chatgpt_region("loc=jp"), None, "小写不算 ✓");
        assert_eq!(chatgpt_region("loc=JPN"), None, "三位不算 ✓");
        assert_eq!(chatgpt_region("ip=1.2.3.4\n"), None, "没有就别说 ✓");
    }
    /// AmazonPV 的三个情形 ✓（这一期里唯一**不需要新档**的服务 ✓）：
    /// 有地区 ⇒ 解锁 ✓ · 没有 ⇒ **未解锁** ✓（不是"没读到" ✓）· 连不上 ⇒ 由调用方不报 ✓。
    #[test]
    fn amazonpv_reads_the_territory_field() {
        assert_eq!(
            amazonpv_verdict(&page(r#"…"currentTerritory": "JP"…"#)),
            Verdict { status: Status::Unlocked, region: Some("JP".into()) }
        );
        // 页面取到了、但**没有**那个字段 ⇒ 未解锁 ✓（页面正常返回就是"对方给了答案" ✓）
        assert_eq!(
            amazonpv_verdict(&page("<html>no territory here</html>")),
            Verdict { status: Status::Blocked, region: None }
        );
    }

    /// ⚠️ 形状检查要挡住"看起来像地区"的别的值 ✓（键名附近还有别的字段 ✓）——
    /// 而**拿到了但形状不对**时，仍然按"没有地区"处理 ✓ ⇒ **未解锁** ✓（与"没有"同一路 ✓）。
    #[test]
    fn amazonpv_regions_must_look_like_regions() {
        assert_eq!(amazonpv_region(r#""currentTerritory":"US""#).as_deref(), Some("US"));
        assert_eq!(amazonpv_region(r#""currentTerritory": "us""#), None, "小写不算 ✓");
        assert_eq!(amazonpv_region(r#""currentTerritory":"USA""#), None, "三位不算 ✓");
        assert_eq!(amazonpv_region(r#""currentTerritory":"""#), None, "空不算 ✓");
        assert_eq!(amazonpv_region("nothing"), None, "没有就别说 ✓");
    }
    /// ⚠️⚠️ **"中国版"不再看正文** ✗✓ —— 它只由**我们最后落在哪个主机**判定 ✓
    /// （[`youtube_is_cn_final`] ✓）。
    /// ⭐ 旧写法是"正文里含 `www.google.cn` ⇒ 中国版" ✗，而那是**误报的来源** ✓：
    /// 用户在**生产那台 US 机器**上实测过 ✓ —— 面板报「中国区」✗，而那一页正文里它出现 **0 次** ✓
    /// （`ad-free` 在 815,530 字节处 ✓ ⇒ 那其实是一页**正常解锁页** ✓）。
    #[test]
    fn youtube_china_is_decided_by_the_final_host_not_by_the_body() {
        // ⚠️ 正文里有那个串 ⇒ **不再**算中国版 ✓（它就是误报的来源 ✓）
        let both = "<html>www.google.cn … ad-free …</html>";
        assert_eq!(
            youtube_verdict(both).status,
            Status::Unlocked,
            "正文里有那个串不作数 ✓ —— 有 ad-free 就是解锁 ✓"
        );
        // ⭐ 真正的凭据是"最后落在了 google.cn" ✓
        assert!(youtube_is_cn_final("https://www.google.cn/premium"));
        assert!(youtube_is_cn_final("https://google.cn/"));
        assert!(!youtube_is_cn_final("https://www.youtube.com/premium"));
        // ⚠️ 后缀判断**不能**写成 `contains` ✗：这两个都不是 google.cn ✓
        assert!(!youtube_is_cn_final("https://notgoogle.cn/x"), "`notgoogle.cn` 不是它 ✓");
        assert!(!youtube_is_cn_final("https://google.cn.evil.example/x"), "后缀必须真的到头 ✓");
        // 而"买不到会员"照旧**排在** ad-free 前面 ✓：那一页里同样可能有 ad-free 字样 ✓
        let noprem = "<html>ad-free Premium is not available in your country</html>";
        assert_eq!(youtube_verdict(noprem).status, Status::NoPrem);
    }

    /// 主机解析 ✓（协议 ✓ 端口 ✓ 大小写 ✓ 用户信息 ✓ —— 无聊且可预测 ✓ 正是它该有的样子 ✓）。
    #[test]
    fn host_parsing_is_boring_and_predictable() {
        assert_eq!(host_of("https://www.google.cn/x?y#z").as_deref(), Some("www.google.cn"));
        assert_eq!(host_of("https://EXAMPLE.com:8443/a").as_deref(), Some("example.com"));
        assert_eq!(host_of("https://u:p@example.com/a").as_deref(), Some("example.com"));
        assert_eq!(host_of("https://example.com").as_deref(), Some("example.com"));
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https://"), None);
    }

    /// YouTube 的四档 ✓ + ⚠️ **"有 ad-free 但取不到地区"仍然算解锁** ✓✓
    ///（不因为缺一格就改判 ✓ —— 与 Netflix/Reddit 同一条规矩 ✓）。
    #[test]
    fn youtube_keeps_unlocked_even_without_a_region() {
        assert_eq!(
            youtube_verdict(r#"<html>"contentRegion":"JP" ad-free</html>"#),
            Verdict { status: Status::Unlocked, region: Some("JP".into()) }
        );
        assert_eq!(
            youtube_verdict("<html>ad-free</html>"),
            Verdict { status: Status::Unlocked, region: None },
            "没有地区不改判 ✓"
        );
        // 什么都没有 ⇒ 不猜 ✓（既不是能用也不是不能用 ✓）
        assert_eq!(youtube_verdict("<html>nothing</html>").status, Status::Unknown);
    }

    /// 地区形状 ✓（两位大写 ✓）+ **键名自己的引号不算值** ✓
    ///（AmazonPV 那一笔就是踩了它 ✓ —— 这里照修好的写法 ✓）。
    #[test]
    fn youtube_regions_must_look_like_regions() {
        assert_eq!(youtube_region(r#""contentRegion":"US""#).as_deref(), Some("US"));
        assert_eq!(youtube_region(r#""contentRegion": "us""#), None, "小写不算 ✓");
        assert_eq!(youtube_region(r#""contentRegion":"USA""#), None, "三位不算 ✓");
        assert_eq!(youtube_region(r#""contentRegion":"""#), None, "空不算 ✓");
        assert_eq!(youtube_region("nothing"), None, "没有就别说 ✓");
    }

    /// 造一个 chunked 正文 ✓（`parts` 是各块的数据 ✓ —— 框架由这里补 ✓）。
    fn chunked(parts: &[&str]) -> String {
        let mut out = String::new();
        for p in parts {
            out.push_str(&format!("{:x}\r\n{}\r\n", p.len(), p));
        }
        out.push_str("0\r\n\r\n");
        out
    }

    /// ⚠️⚠️ **标记跨 chunk 边界** ✗✗ —— 这是"裸读会读错"的那一条 ✓：
    /// 分块框架会**插在标记中间** ✓ ⇒ 判据看不到 `"contentRegion"` ✓
    /// ⇒ **状态照旧、地区静默消失** ✓（本仓最怕的那类错 ✓）。
    #[test]
    fn a_marker_split_across_chunks_survives() {
        let raw = chunked(&["<html>\"contentReg", "ion\":\"HK\" ad-free</html>"]);
        assert_eq!(youtube_region(&raw), None, "⚠️ **裸读就是读不到** ✓（先把这条错钉住 ✓）");
        let out = dechunk(&raw);
        assert!(out.contains("\"contentRegion\":\"HK\""), "拼回去之后标记必须完整 ✓");
        assert_eq!(youtube_region(&out).as_deref(), Some("HK"), "剥掉框架 ⇒ 地区回来了 ✓");
        assert_eq!(youtube_verdict(&out).status, Status::Unlocked);
    }

    /// 剥框架的三条边界 ✓：普通块 ✓ · 带扩展 ✓ · **截断要交出已有的正文** ✓✗
    #[test]
    fn dechunk_strips_the_framing_and_never_eats_the_body() {
        assert_eq!(dechunk(&chunked(&["hello ", "world"])), "hello world");
        // 块大小后面可以带 `;扩展` ✓（RFC 允许 ✓，不处理的话整条正文都会读不到 ✓）
        assert_eq!(dechunk("4;foo=bar\r\nbody\r\n0\r\n\r\n"), "body");
        // ⚠️ 我们读到一半就停是**常事** ✓ ⇒ 截断**必须交出已拿到的** ✓，不能整条丢掉 ✓
        let full = chunked(&["aaaa", "bbbb"]);
        assert_eq!(dechunk(&full[..10]), "aaaa", "截断 ⇒ 拿到多少算多少 ✓");
        // ⚠️ 第一行就不是块大小 ⇒ **原样返回** ✓（宁可不剥，也不吃掉正文 ✓）
        assert_eq!(dechunk("这不是 chunked"), "这不是 chunked");
        assert_eq!(dechunk(""), "");
    }

    /// `assemble` 只在响应自己说 chunked 时才动手 ✓ —— 头部**原样保留** ✓（状态码与跳转还要用 ✓）。
    #[test]
    fn assemble_dechunks_only_when_the_response_says_so() {
        let raw =
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}", chunked(&["hello ", "world"]));
        let text = assemble(raw.as_bytes());
        assert!(text.ends_with("hello world"), "chunked ⇒ 剥掉框架 ✓");
        assert!(text.contains("Transfer-Encoding: chunked"), "头部不动 ✓");
        let plain = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(assemble(plain.as_bytes()), plain, "不是 chunked ⇒ 一个字都不动 ✓");
    }

    /// 块边界落在多字节字符中间时，**必须不 panic**。
    ///
    /// 块大小是字节数，而 `&str` 按下标切要求落在字符边界上 —— 旧实现在这里 panic，
    /// release 是 `panic = "abort"` ⇒ 整个 agent 被 abort，而 `remember()` 还没执行、
    /// 重启后立刻再探 ⇒ 每 5 秒一轮的崩溃循环。所以这条用例守的是"能不能继续跑"。
    #[test]
    fn dechunk_splits_on_bytes_not_characters() {
        // "中" 占 3 字节，而声明块大小 1 ⇒ 边界正好落在它中间。
        let out = dechunk("1\r\n中\r\n0\r\n\r\n");
        assert!(!out.is_empty(), "读到的字节要交出去，不能丢掉");
        // 正常的块、含中文，边界对齐 ⇒ 原样还原。
        let ok = dechunk("3\r\n中\r\n3\r\nabc\r\n0\r\n\r\n");
        assert_eq!(ok, "中abc");
    }

    /// ⚠️ "够了就停"的那个闸 ✓ —— 停早了会把**地区**弄丢 ✓✗，所以 `ad-free` 必须**连地区一起**才算够 ✓。
    #[test]
    fn youtube_stops_reading_only_when_the_verdict_is_settled() {
        assert!(!youtube_decided("<html>ad-free</html>"), "只有 ad-free ⇒ 还不能停 ✓（地区可能在后头 ✓）");
        assert!(youtube_decided(r#"<html>"contentRegion":"HK" ad-free</html>"#), "两者齐了 ⇒ 停 ✓");
        // ⚠️ **域名不是停手信号** ✗✗ —— 它曾经是，但 `youtube_verdict` 早就不拿它判中国版了；
        // 留着它只会让我们在 32KB 处停手，把 815KB 处的 `ad-free` 挡在外面（判成"没读明白"）。
        assert!(!youtube_decided("<html>www.google.cn</html>"), "域名出现不等于读够了");
        // 禁会员那档没有地区 ✓、见到就能定案 ✓
        assert!(youtube_decided("<html>Premium is not available in your country</html>"));
        assert!(!youtube_decided("<html>nothing yet</html>"), "什么都没读到 ⇒ 继续读 ✓");
    }

    /// ⚠️ 地区取**最后一处** ✓（参考的 `sed` 里 `.*` 贪婪 ⇒ 它也是最后一处 ✓；我们此前取第一处 ✗）。
    #[test]
    fn youtube_region_takes_the_last_one() {
        assert_eq!(
            youtube_region(r#""contentRegion":"US" …… "contentRegion":"HK""#).as_deref(),
            Some("HK"),
            "两处都有 ⇒ 取最后一处 ✓"
        );
        // ⚠️ "先给值、后给空"才是这一条真正的分叉点 ✓：最后一处不合法 ⇒ 就是"取不到" ✓
        assert_eq!(youtube_region(r#""contentRegion":"US" "contentRegion":"""#), None);
    }

    /// ⚠️⚠️ **相对跳转必须认** ✗✗ —— 实测（2026-10-13）：`https://www.primevideo.com`
    /// 的 302 给的就是相对路径 ✓，而我们此前只接受 `https://` 开头 ⇒ **整个服务取不到页** ✗。
    /// 而"只跟 https"那条安全规矩**不动** ✓。
    #[test]
    fn a_relative_redirect_is_resolved_against_the_current_url() {
        let cur = "https://www.primevideo.com";
        assert_eq!(
            resolve_location(cur, "/offers/nonprimehomepage?ref_=dv_web_force_root").as_deref(),
            Some("https://www.primevideo.com/offers/nonprimehomepage?ref_=dv_web_force_root"),
            "根相对 ✓（实测就是这一条 ✓）"
        );
        assert_eq!(
            resolve_location(cur, "https://a.example/b").as_deref(),
            Some("https://a.example/b"),
            "绝对 https 照旧 ✓"
        );
        assert_eq!(
            resolve_location(cur, "//a.example/b").as_deref(),
            Some("https://a.example/b"),
            "协议相对 ✓"
        );
        assert_eq!(
            resolve_location("https://a.example/x/y", "z").as_deref(),
            Some("https://a.example/x/z"),
            "路径相对 ⇒ 拼到当前路径最后一个 `/` 之前 ✓"
        );
        // ⚠️ 安全规矩**不动** ✓：明文一律拒绝 ✓（那比"取不到页"糟得多 ✓）
        assert_eq!(resolve_location(cur, "http://a.example/b"), None, "明文必须拒绝 ✓");
        // ⚠️ 其它协议不能被当路径拼 ✓（不然会造出一个同主机的怪地址 ✓）
        assert_eq!(resolve_location(cur, "ftp://a.example/b"), None);
        assert_eq!(resolve_location(cur, ""), None);
        assert_eq!(resolve_location("http://a.example", "/x"), None, "起点就不是 https ⇒ 拒绝 ✓");
    }

    /// ⚠️⚠️ **一个"不像产品页"的响应，永远不许变成结论** ✗✗ —— 这一整类的回归闸 ✓。
    /// 实测依据 ✓（2026-10-13）：真实页面 506–944 KB ✓，一次限流只有 **521 字节** ✓。
    #[test]
    fn a_response_too_small_to_be_the_product_is_never_a_verdict() {
        // ⚠️ 那个"限流页"的样子 ✓ —— 它里面当然不会有我们要找的标记 ✓
        let tiny = "<html><head><title>503</title></head><body>Sorry, something went wrong.</body></html>";
        assert!(tiny.len() < PAGE_FLOOR, "这条测试的前提：它确实在地板以下 ✓");
        assert_eq!(amazonpv_verdict(tiny).status, Status::Unknown, "AmazonPV：不许说未解锁 ✓");
        // ⚠️ Netflix 这条更值钱 ✓：两个小页面以前会一路走到 else ⇒ 判「**解锁**」✓✗（绿错值 ✓）
        assert_eq!(netflix_verdict(tiny, tiny).status, Status::Unknown, "Netflix：更不许说解锁 ✓");
        assert_eq!(reddit_verdict(200, tiny).status, Status::Unknown, "Reddit：200 的小页不是页面 ✓");
        // ⚠️ 而**够大**的页面照旧按原来的判据走 ✓（别把正常情形也拦了 ✓）
        let big = "x".repeat(PAGE_FLOOR + 1);
        assert_eq!(amazonpv_verdict(&big).status, Status::Blocked, "够大但没有那个键 ⇒ 仍是未解锁 ✓");
        assert_eq!(netflix_verdict(&big, &big).status, Status::Unlocked, "够大、没有 Oh no! ⇒ 仍是解锁 ✓");
    }

    /// ⚠️ **TikTok 没有"被墙"这一档** ✗ —— 参考的兜底是 Failed（失败）✓，
    /// 它唯一给 Block 的分支是死代码 ✓（审计逐行复核过 ✓）。
    #[test]
    fn tiktok_falls_back_to_unknown_not_blocked() {
        let blocked_looking = "<html>".to_string() + &"y".repeat(PAGE_FLOOR) + "</html>";
        assert_eq!(tiktok_verdict(&blocked_looking, "").status, Status::Unknown);
        assert_eq!(tiktok_verdict("", "").status, Status::Unknown);
    }

    /// ⚠️ "有一边没读到"要说出来 ✓；"两边都没读到"才不报 ✓（网络故障不是结论 ✓）。
    #[test]
    fn chatgpt_says_unknown_when_only_one_side_could_be_read() {
        let api = r#"{"unsupported_country": true}"#;
        let ios = "<html>VPN</html>";
        // 两边都读到 ⇒ 照原判据 ✓（API 有问题 + favicon 403 ⇒ 未解锁 ✓）
        assert_eq!(chatgpt_from_results(Some(api), Some(ios), 403).map(|v| v.status), Some(Status::Blocked));
        // ⚠️ 只有一边 ⇒ **没读明白**（不是沉默 ✗，也不是猜 ✓）
        assert_eq!(chatgpt_from_results(Some(api), None, 0).map(|v| v.status), Some(Status::Unknown));
        assert_eq!(chatgpt_from_results(None, Some(ios), 0).map(|v| v.status), Some(Status::Unknown));
        // 两边都没读到 ⇒ **什么都不报** ✓
        assert!(chatgpt_from_results(None, None, 0).is_none());
    }

    /// ⚠️ **夹具要够大** ✗✓ —— 判据现在先过一道"这像不像产品页"的地板 ✓（[`PAGE_FLOOR`] ✓），
    /// 而这里过去写的都是 `"<html>…</html>"` 这种小串 ✓ ⇒ 它们会被**正确地**判成"没读明白" ✓。
    /// ⇒ 这个助手把夹具补到**页面尺度** ✓，让那些测试继续测**判据本身** ✓（而不是在测地板 ✓）。
    /// ⚠️ 填充用的是 `=` ✓ —— 不会碰巧带上任何判据要找的标记 ✓。
    fn page(s: &str) -> String {
        // ⚠️⚠️ **空串不补** ✗✓ —— "正文是空的"是一个**独立的情形** ✓（判据里它自己有一支 ✓，
        // 说的是"这次什么都没读到" ⇒ `unknown` ✓）。补成页面尺度会把它变成"两个正常页面" ✓✗
        // ⇒ 判成**解锁** ✓ —— ⭐ 这一条是那条测试当场抓住的 ✓（我先写的版本正是这么错的 ✓）。
        if s.trim().is_empty() {
            return s.to_string();
        }
        let mut out = String::from(s);
        if out.len() < PAGE_FLOOR + 1 {
            out.push_str(&"=".repeat(PAGE_FLOOR + 1 - out.len()));
        }
        out
    }

    /// ⚠️⚠️ **region 取最后一处** ✗✓ —— 参考的 `sed` 里 `.*` 是贪婪的 ✓；
    /// 而"先给值、后给空"的页面正是这一条的分叉点 ✓（与 YouTube 那条同一规矩 ✓）。
    #[test]
    fn tiktok_region_takes_the_last_one() {
        assert_eq!(
            tiktok_region(r#"{"region":"US"} … {"region":"JP"}"#).as_deref(),
            Some("JP"),
            "两处都有 ⇒ 取最后一处 ✓"
        );
        assert_eq!(tiktok_region(r#"{"region":"US"} {"region":""}"#), None, "最后一处不合法 ⇒ 取不到 ✓");
        assert_eq!(tiktok_region(r#"{"region":"us"}"#), None, "小写不算 ✓");
    }

    /// ⚠️⚠️ **extra 里的头要"替换"默认那份，不是叠加** ✗✗ ——
    /// 用户要的 TikTok 那一次正是这种情形 ✓：参考给 `-H "Accept: …"`（替换 curl 默认头 ✓），
    /// 而我们是硬写 `Accept: */*` 再**追加** ⇒ 实际发出去**两个** ✓✗。
    #[test]
    fn a_header_in_extra_replaces_the_default_instead_of_stacking() {
        // extra 给了 Accept ⇒ 只能有一个 ✓，而且留下的必须是 extra 那个 ✓
        let r = build_request("/premium", "www.tiktok.com", "Accept: text/html,application/xhtml+xml");
        assert_eq!(r.matches("ccept:").count(), 1, "只能发一个 Accept ✓");
        assert!(r.contains("Accept: text/html"), "留下的应当是 extra 那个 ✓");
        assert!(!r.contains("Accept: */*"), "默认那份必须让位 ✓");
        // 没给 ⇒ 默认那份照旧 ✓
        let d = build_request("/x", "example.com", "");
        assert_eq!(d.matches("ccept:").count(), 1);
        assert!(d.contains("Accept: */*"));
        // UA 同理 ✓（ChatGPT 的 favicon 那次要装成 Edge ✓）
        let e = build_request("/favicon.ico", "chatgpt.com", "user-agent: Edge/119");
        // ⚠️ 数的时候**要按小写数** ✗ —— HTTP 头名**不区分大小写** ✓（规范如此 ✓），
        // 而 extra 那行是小写的 ✓ ⇒ 拿大写去数会数出 0 ✓✗ —— 我第一版就是这样把**测试**写错的 ✓
        //（代码是对的 ✓；是断言糙了 ✓）。
        assert_eq!(e.to_ascii_lowercase().matches("user-agent:").count(), 1, "只能发一个 UA ✓");
        assert!(e.contains("user-agent: Edge/119"));
        // ⚠️ `Host` **不许**被 extra 覆盖 ✗ —— 它必须与我们要连的主机一致 ✓
        let h = build_request("/x", "example.com", "Host: evil.example");
        assert!(h.contains("Host: example.com"));
        assert!(!h.contains("evil.example"));
        // HTTP 头不区分大小写 ✓ ⇒ 判断也要如此 ✓
        // ⚠️⚠️ 数之前**先转小写** ✗ —— 我在这里**第二次**犯同一个错 ✓✗：
        // 原串里是**大写** `ACCEPT:` ✓，而我拿小写 `ccept:` 去数 ⇒ 数出 0 ✓
        //（⭐ 代码是对的 ✓ —— 它内部就是 `to_ascii_lowercase()` 判断的 ✓；
        //  默认那份**已经被正确丢掉**了 ✓）。HTTP 头名不区分大小写 ✓ ⇒ 数法也要如此 ✓。
        assert_eq!(
            build_request("/x", "e.com", "ACCEPT: y").to_ascii_lowercase().matches("ccept:").count(),
            1,
            "大写给小写都得只发一个 ✓"
        );
    }

    /// 取最后一处：参考那行是贪婪匹配。与 YouTube / TikTok 同一规矩。
    #[test]
    fn netflix_region_takes_the_last_one() {
        assert_eq!(
            netflix_region(
                r#"{"id":"US","countryName":"United States"} … {"id":"JP","countryName":"Japan"}"#
            )
            .as_deref(),
            Some("JP"),
            "两处都有 ⇒ 取最后一处 ✓"
        );
        assert_eq!(netflix_region(r#"{"id":"US"} {"id":""}"#), None, "最后一处不合法 ⇒ 取不到 ✓");
        assert_eq!(netflix_region(r#"{"id":"us"}"#), None, "小写不算 ✓");
        assert_eq!(netflix_region("nothing here"), None);
    }

    /// 取第一个有效的：参考是第一个非空。差别只在 第一处是空、第二处有值。
    #[test]
    fn reddit_region_takes_the_first_usable_one() {
        assert_eq!(
            reddit_region(r#"country="" … country="JP""#).as_deref(),
            Some("JP"),
            "第一处是空 ⇒ 必须继续找，而不是放弃 ✓"
        );
        assert_eq!(reddit_region(r#"country="US" country="JP""#).as_deref(), Some("US"), "第一个有效 ✓");
        assert_eq!(reddit_region(r#"country="jp" country="JPN""#), None, "都不合法 ⇒ 不给 ✓");
    }

    /// 诊断那一行只列**找到的**标记（免得一行里全是 =0，反而不好读）。
    #[test]
    fn a_diagnostic_line_counts_the_markers_it_finds() {
        let line = diag_line("https://example/x", 200, "<html>ad-free ad-free contentRegion Oh no!</html>");
        assert!(line.contains("status=200"), "状态码要在 ✓: {line}");
        assert!(line.contains("bytes="), "长度要在 ✓: {line}");
        assert!(line.contains("ad-free=2"), "数出现的次数 ✓: {line}");
        assert!(line.contains("contentRegion=1"), "{line}");
        assert!(line.contains("Oh no!=1"), "{line}");
        // 没找到的**不出现** ✓
        assert!(!line.contains("currentTerritory"), "{line}");
        assert!(!line.contains("VPN"), "{line}");
        assert!(!line.contains("Please wait"), "{line}");
    }

    /// ⚠️⚠️ **头部里的字符串不算判据** ✗✗ —— 这条是 2026-10-15 那次事故的回归闸。
    ///
    /// YouTube 的响应头里有一条 `connection-allowlist-report-only`，名单里含
    /// `https://www.google.cn`。判据当时拿**整份响应**去找它 ⇒ 第一批字节就命中 ⇒
    /// 读到 33 KB 就停手 ⇒ 真正的标记（818 KB 处的 `ad-free`）永远读不到 ⇒ 面板报"没读明白"。
    /// 本地怎么验都验不出来，因为 curl 下来的是正文、没有头部。
    #[test]
    fn markers_in_the_response_headers_do_not_count() {
        let head = "HTTP/1.1 200 OK\r\nconnection-allowlist-report-only: (\"https://www.google.cn\")\r\n\r\n";
        let text = format!("{head}<html>a normal page without markers</html>");
        assert!(text.contains("www.google.cn"), "整份响应里当然有它 ✓");
        assert!(!body_of(&text).contains("www.google.cn"), "但正文里没有 ✓");
        // 注意这里断言的是**调用点的契约**，不是那个函数变得更聪明了。
        // youtube_decided 本身就是个纯扫描器：它只认字符串，不知道哪儿是头部。
        // 所以**喂给它什么**才是这条 bug 的所在。我第一版把断言写成
        // !youtube_decided(&text)，那等于要求函数自己会剥头部，是断言写错了。
        // ⚠️ 现在这一条更强：扫描器**完全不认**这个域名了 —— 所以无论它在头部还是正文里，
        // 都不可能再触发"提前停手"。旧断言写的是 `assert!(...)`，那时它确实会命中。
        assert!(!youtube_decided(&text), "域名在头部也不该触发停手");
        assert!(!youtube_decided(body_of(&text)), "只看正文时就不会命中");
        // 正文里真的有标记时照旧要停 ✓（别把孩子跟水一起倒了）
        let real = format!("{head}<html>ad-free and \"contentRegion\":\"US\"</html>");
        assert!(youtube_decided(body_of(&real)), "正文里有标记 ⇒ 该停 ✓");
        // 没有分界时整份算正文 ✓（宁可多给，也不要交出空串把判据饿死）
        assert_eq!(body_of("<html>no boundary</html>"), "<html>no boundary</html>");
    }
}
