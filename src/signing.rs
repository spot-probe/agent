//! 发布物签名：agent 只接受**用这把公钥签过**的升级。
//!
//! **这是整个远程升级功能的地基**：没有它，"hub 被拿下"就等于"整个机队可以被换上任意二进制"。
//! 公钥**编译进二进制**，不是配置项、也不能由 hub 改 —— 换信任根必须手动升一次 agent，
//! 那是这个方案天然的代价（也是它的强度所在）。
//!
//! 私钥只在发布流程里（CI 的 Environment 批准 / 你本机），**从不进仓库**；
//! 仓库里那份 `.pub` 是给人核对用的，公开无害。
//!
//! 只用 `minisign-verify`（**零依赖**、只验签、代码很短 ✓）—— 信任根压在越小、越可审计的东西上越好。

use anyhow::{anyhow, Result};
use minisign_verify::{PublicKey, Signature};

/// minisign 公钥（`agent-signing-key.pub` 的第二行，逐字抄来）。
pub const PUBLIC_KEY: &str = "RWTUeWC3rxsjagHeCDRqDbIUXN2KJjLi5zo/Wb3TDjGWjyx5GBgaRsSF";

// 第一期只落"信任根 + 能验签"：下面两个函数**还没有调用者**，第②期（远程升级）才接上。
// 按本仓惯例（同 hub 的 `ping_records_hourly`）标 `#[allow(dead_code)]` 并写明原因，
// 而不是删掉再写回来 —— 删掉会让"信任根已经就位"这件事看不出来。
#[allow(dead_code)]
/// 解出内置公钥。抄错一个字符就会在这里失败 —— 而不是等到某台机器上"签名怎么都验不过"。
pub fn public_key() -> Result<PublicKey> {
    PublicKey::from_base64(PUBLIC_KEY.trim()).map_err(|e| anyhow!("内置公钥解不开：{e}"))
}

#[allow(dead_code)]
/// 校验一段字节的签名（`sig_text` 是 `.sig` 文件的**全文**：两条 comment + 两行 base64）。
///
/// 第三个参数 `false` 是 minisign 的**标准模式**（非预哈希）—— 发布时用 `minisign -S` 默认就是它。
pub fn verify_bytes(data: &[u8], sig_text: &str) -> Result<()> {
    let sig = Signature::decode(sig_text).map_err(|e| anyhow!("签名文件解不开：{e}"))?;
    public_key()?.verify(data, &sig, false).map_err(|e| anyhow!("签名不匹配：{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内置公钥必须能解析 —— 这条比"长度是 42"更硬：`from_base64` 会校验它的内部结构。
    #[test]
    fn the_baked_in_key_parses() {
        public_key().expect("内置公钥必须能解出来");
    }

    /// **反例：格式完全合法、但用另一把密钥签的签名，必须验不过。**
    ///
    /// 这条签名取自 `minisign-verify` crate 自己的文档（对内容 `test`、由它示例里那把密钥签的）——
    /// 也就是说它**一定能被解码**、结构完全正确，只是**不是我们这把密钥签的**。
    /// 如果这条测试过了（返回 Ok），说明校验根本没在做事，那比没有签名更糟：它给人安全感。
    #[test]
    fn a_valid_signature_from_another_key_must_fail() {
        const OTHER_KEY_SIG: &str = "untrusted comment: signature from minisign secret key
RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=
trusted comment: timestamp:1555779966\tfile:test
QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==";
        assert!(
            verify_bytes(b"test", OTHER_KEY_SIG).is_err(),
            "另一把密钥签的签名必须被拒 —— 否则校验形同虚设"
        );
    }

    /// 乱造的签名也必须被拒（连解码都过不去）。
    #[test]
    fn garbage_signatures_are_rejected() {
        assert!(verify_bytes(b"anything", "not a signature").is_err());
        assert!(verify_bytes(b"anything", "").is_err());
    }

    /// **正例：这条真实的签名必须被我们编进 agent 的那把公钥验过。**
    ///
    /// 夹具是维护者用自己的私钥、按发布流程里**同一条命令**签出来的：
    /// `minisign -S -s ~/agent-signing-key.key -m tests/fixtures/hello.txt -t fixture`
    /// —— 也就是说它证明了"**发布时怎么签**"与"**agent 怎么验**"这两端是通的，
    /// 而这是整个远程升级方案里唯一必须绝对可靠的一环。
    ///
    /// 夹具入仓库无害：签名不是秘密，公钥本来就是公开的。而且这样一来，
    /// **任何人 clone 下来跑 `cargo test` 都能独立确认这个信任根是自洽的**。
    #[test]
    fn the_real_signature_verifies() {
        const DATA: &[u8] = include_bytes!("../tests/fixtures/hello.txt");
        const SIG: &str = include_str!("../tests/fixtures/hello.txt.minisig");
        verify_bytes(DATA, SIG).expect("维护者签的夹具必须验得过");
    }

    /// 而且**改一个字节就验不过** —— 否则"验签"只证明"有个签名在那儿"，证明不了内容没被动过。
    #[test]
    fn a_tampered_payload_is_rejected() {
        const SIG: &str = include_str!("../tests/fixtures/hello.txt.minisig");
        let mut tampered = include_bytes!("../tests/fixtures/hello.txt").to_vec();
        tampered[0] ^= 0x01;
        assert!(verify_bytes(&tampered, SIG).is_err(), "被改过一字节的内容必须验不过");
    }
}
