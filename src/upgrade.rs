//! 远程升级的**接收与校验**（A 期：只证明链路，**绝不替换自己**）。
//!
//! 协议（都在同一条已认证的 WS 上，不引入任何 HTTP 客户端）：
//!
//! ```text
//! hub → agent  文本 rpc: {"method":"upgrade.verify","params":{"version":…,"sig":…,"size":…}}
//! hub → agent  二进制帧 ×N（正好 size 字节）
//! agent → hub  文本 rpc: {"method":"upgrade.report","params":{"ok":…,"reason":…,"version":…}}
//! ```
//!
//! **为什么 `size` 必须写在公告里**：二进制帧在 `session` 的循环里原本是被忽略的
//! （`Some(Ok(_)) => {}`），所以要自己收；而"收多少"必须事先知道，否则就得再发明一个
//! 终止帧 —— 那只是多一种出错方式。
//!
//! **不校 sha256**：minisign 的签名本来就是**对这段字节**算的，改一个字节就验不过
//! （`signing::tests::a_tampered_payload_is_rejected` 就是这条）。再校一遍 sha256 只是
//! 重复同一件事，却要给 agent 加一个 `sha2` 依赖。公告里的 sha256 仅用于回报与人工对照。
//!
//! **这一期不写任何持久文件**：验过即删。替换与回滚是下一期的事。

use anyhow::Result;

use crate::signing;

/// 版本 `a` 是否比 `b` 新。**逐段比数值，不能比字符串**：
/// `"1.10.0" < "1.9.0"` 按字符串为真，于是刚跨到两位数的次版本时，反回滚会把真正的新版本
/// 拒之门外 —— 而那种 bug 只在"刚好升到 1.10"时出现，最容易被漏掉。
fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v').split(['.', '-', '+']).map(|p| p.parse().unwrap_or(0)).collect()
    };
    let (x, y) = (parts(a), parts(b));
    for i in 0..x.len().max(y.len()) {
        let (l, r) = (x.get(i).copied().unwrap_or(0), y.get(i).copied().unwrap_or(0));
        if l != r {
            return l > r;
        }
    }
    false
}

/// 已经公告、正在等字节的一次升级。
#[derive(Debug, Clone)]
pub struct Pending {
    pub version: String,
    pub sig: String,
    pub size: usize,
}

/// 状态机每一步的产出。`None` 表示"这条帧与我无关"。
#[derive(Debug)]
pub enum Step {
    /// 公告被接受，开始等 `size` 字节。
    Collecting(usize),
    /// 拒绝，附上给 hub 的原因。
    Reject(String),
    /// 有结论了（验过、或中途失败）。**自带 version**，于是回报时不必再去别处找它。
    Done { ok: bool, reason: String, version: String },
}

#[derive(Default)]
pub struct State {
    open: Option<(Pending, Vec<u8>)>,
}

/// 一次升级最多收多大。与 hub 侧的分片上限无关：agent 只认签名，签名过了才谈大小。
pub const MAX: usize = 64 * 1024 * 1024;

impl State {
    /// 处理一条**文本** rpc。`allowed` 是本机开关（`--allow-remote-upgrade`），
    /// `secure` 表示这条连接是否可信（wss，或 loopback 上的明文）。
    pub fn text(&mut self, params: &serde_json::Value, allowed: bool, secure: bool) -> Option<Step> {
        let s = |k: &str| params.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
        let version = s("version");
        // 三道门，顺序刻意如此：**先看本机愿不愿意**（这是本机的事，报给 hub 也没用），
        // 再看这条连接可不可信，最后才看公告本身是否完整。
        if !allowed {
            return Some(Step::Reject("本机未开启远程升级（--allow-remote-upgrade）".into()));
        }
        if !secure {
            return Some(Step::Reject("非加密连接上不接受升级".into()));
        }
        let size = params.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let sig = s("sig");
        if version.is_empty() || sig.is_empty() || size == 0 || size > MAX {
            return Some(Step::Reject("升级公告不完整或过大".into()));
        }
        // **反回滚**：绝不接受不比现在新的版本。
        if !newer(&version, env!("CARGO_PKG_VERSION")) {
            return Some(Step::Reject(format!(
                "版本不比当前新（当前 {}，收到 {version}）",
                env!("CARGO_PKG_VERSION")
            )));
        }
        self.open = Some((Pending { version, sig, size }, Vec::with_capacity(size.min(1 << 20))));
        Some(Step::Collecting(size))
    }

    /// 处理一个**二进制**帧。没有正在进行的升级时返回 `None`（与从前一样忽略它）。
    pub fn binary(&mut self, data: &[u8]) -> Option<Step> {
        let (pending, buf) = self.open.as_mut()?;
        if buf.len() + data.len() > pending.size {
            let version = pending.version.clone();
            self.open = None;
            return Some(Step::Done {
                ok: false, reason: "收到的字节多于公告的长度".into(), version
            });
        }
        buf.extend_from_slice(data);
        if buf.len() < pending.size {
            return Some(Step::Collecting(pending.size - buf.len()));
        }
        let (pending, buf) = self.open.take().expect("刚判断过是 Some");
        let outcome = self.finish(&pending, &buf);
        Some(outcome)
    }

    /// 收齐之后的收尾：验签 → **不落盘** → 给出结论。
    ///
    /// 刻意**只验不写**：这一期的价值是"证明 hub 能推、agent 能验"，不是换二进制。
    fn finish(&self, pending: &Pending, buf: &[u8]) -> Step {
        // 结论自带 version：回报时不必再去别处找它。
        let version = pending.version.clone();
        match signing::verify_bytes(buf, &pending.sig) {
            Ok(()) => Step::Done {
                ok: true,
                reason: format!("签名校验通过（{} 字节，未替换）", buf.len()),
                version,
            },
            Err(e) => Step::Done { ok: false, reason: format!("签名校验失败：{e}"), version },
        }
    }

    // 没有 abort()：状态是 `session` 里的局部量，连接一断它就跟着没了 ——
    // 跨会话残留半份升级数据这件事不可能发生，所以没有需要清的东西。
}

/// 把一次结果包成回报给 hub 的 rpc。
pub fn report(ok: bool, reason: &str, version: &str) -> Result<tokio_tungstenite::tungstenite::Message> {
    Ok(crate::notify("upgrade.report", serde_json::json!({ "ok": ok, "reason": reason, "version": version })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/hello.txt");
    const FIXTURE_SIG: &str = include_str!("../tests/fixtures/hello.txt.minisig");

    fn announce(sig: &str, size: usize, version: &str) -> serde_json::Value {
        json!({ "version": version, "sig": sig, "size": size })
    }

    /// **本机开关关着 → 直接拒**，而且**连字节都不收**。
    #[test]
    fn refuses_when_the_local_switch_is_off() {
        let mut st = State::default();
        let step = st.text(&announce(FIXTURE_SIG, FIXTURE.len(), "99.0.0"), false, true);
        assert!(matches!(step, Some(Step::Reject(_))), "开关关着必须拒");
        assert!(st.binary(FIXTURE).is_none(), "拒了之后二进制帧不该被当成升级数据");
    }

    /// **非可信连接 → 拒**（明文 + 非 loopback 的中间人可以直接推一个升级）。
    #[test]
    fn refuses_on_an_insecure_connection() {
        let mut st = State::default();
        let step = st.text(&announce(FIXTURE_SIG, FIXTURE.len(), "99.0.0"), true, false);
        assert!(matches!(step, Some(Step::Reject(_))), "明文连接必须拒");
    }

    /// **版本比较必须是数值比较**：`"1.10.0"` 比 `"1.9.0"` 新。
    /// 按字符串比会得出**相反**的结论 —— 于是刚跨到两位数的次版本时，
    /// 反回滚会把真正的新版本挡住（这条测试就是那个 bug 的活证据）。
    #[test]
    fn version_comparison_is_numeric_not_lexical() {
        assert!(newer("1.10.0", "1.9.0"), "1.10.0 比 1.9.0 新");
        assert!(!newer("1.9.0", "1.10.0"));
        assert!(newer("2.0.0", "1.99.99"));
        assert!(!newer("1.1.2", "1.1.2"), "同版本不算更新");
        assert!(newer("v1.2.4", "1.2.3"), "带 v 前缀也要能比");
    }

    /// **反回滚**：不比当前新的版本一律拒。
    #[test]
    fn refuses_a_version_that_is_not_newer() {
        let mut st = State::default();
        let step = st.text(&announce(FIXTURE_SIG, FIXTURE.len(), "0.0.1"), true, true);
        match step {
            Some(Step::Reject(why)) => assert!(why.contains("不比当前新"), "原因要说清楚：{why}"),
            other => panic!("应当拒绝，得到 {other:?}"),
        }
    }

    /// **正路：收齐 → 验签 → 通过（且不落盘）。** 用的是那条真夹具与真签名。
    #[test]
    fn a_real_signed_payload_verifies() {
        let mut st = State::default();
        let step = st.text(&announce(FIXTURE_SIG, FIXTURE.len(), "99.0.0"), true, true);
        assert!(matches!(step, Some(Step::Collecting(n)) if n == FIXTURE.len()), "应当开始收字节");
        // 分两片喂，模拟真实的分帧
        let (a, b) = FIXTURE.split_at(FIXTURE.len() / 2);
        assert!(matches!(st.binary(a), Some(Step::Collecting(_))), "还没收齐");
        match st.binary(b) {
            Some(Step::Done { ok, reason, .. }) => {
                assert!(ok, "真签名必须验过：{reason}");
                assert!(reason.contains("未替换"), "这一期不替换，回报里要写明");
            }
            other => panic!("应当收齐并验过，得到 {other:?}"),
        }
    }

    /// **改过一字节 → 验不过**，而且原因要能回报出去。
    #[test]
    fn a_tampered_payload_fails_verification() {
        let mut st = State::default();
        st.text(&announce(FIXTURE_SIG, FIXTURE.len(), "99.0.0"), true, true);
        let mut bad = FIXTURE.to_vec();
        bad[0] ^= 0x01;
        match st.binary(&bad) {
            Some(Step::Done { ok, reason, .. }) => {
                assert!(!ok, "改过一字节必须验不过");
                assert!(reason.contains("签名校验失败"), "原因要写清楚：{reason}");
            }
            other => panic!("应当得出「失败」的结论，得到 {other:?}"),
        }
    }

    /// **多给的字节 → 拒**（公告说多少就收多少，多一个字节都不认）。
    #[test]
    fn refuses_more_bytes_than_announced() {
        let mut st = State::default();
        st.text(&announce(FIXTURE_SIG, FIXTURE.len() - 1, "99.0.0"), true, true);
        match st.binary(FIXTURE) {
            Some(Step::Done { ok, .. }) => assert!(!ok, "多于公告长度必须拒"),
            other => panic!("应当拒绝，得到 {other:?}"),
        }
    }

    /// 没有进行中的升级时，二进制帧仍应被忽略（与从前一样）—— 这一步不能改变既有行为。
    #[test]
    fn binary_frames_are_still_ignored_when_no_upgrade_is_pending() {
        let mut st = State::default();
        assert!(st.binary(b"anything").is_none(), "没有进行中的升级时二进制帧应被忽略（与从前一致）");
    }
}
