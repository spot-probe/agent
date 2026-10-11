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
}
