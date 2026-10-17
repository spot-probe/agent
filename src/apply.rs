// 还没接线：这一半（文件层）先落地并用真文件测过，接线（什么时候按下去、起来之后怎么自证）
// 是下一步。按本仓惯例标注并写明原因，而不是把已经写好、已经测过的东西删掉再写一遍。
#![allow(dead_code)]

//! ④：把验过的二进制**换上去**，以及在它起不来时**换回来**。
//!
//! 这里刻意只做**文件层面**的事，而且全部可测：路径由 `current_exe()` 推出，
//! 每一步都能在一个临时目录里用真文件跑一遍（`rename`/`chmod` 都是真的）。
//! 真正危险的部分（什么时候按下这个动作、起来之后怎么自证）留在调用方，见下。
//!
//! **"起不来就回滚"这件事 agent 自己做不到** —— 新二进制如果瞬间崩溃，它不会运行，
//! 也就没有代码去回滚。能兜住那种情况的是 systemd（`install.sh` 写的是 `Restart=always`），
//! 以及 `StartLimitIntervalSec` 重试若干次后放弃。本模块负责的是**另一半**：
//! "能启动、但连不上 hub"那种**半死**状态 —— 那种情况下 agent 还活着，所以它能自己回滚。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// 一次替换涉及的全部路径。都由当前可执行文件的位置推出，所以**不需要配置**：
/// agent 就在它该在的地方，`.prev` 与 marker 都在它旁边。
#[derive(Debug, Clone)]
pub struct Plan {
    pub exe: PathBuf,
    pub staged: PathBuf,
    pub prev: PathBuf,
    pub marker: PathBuf,
}

impl Plan {
    /// 以 `exe` 为"正在运行的自己"构造。
    pub fn at(exe: impl AsRef<Path>) -> Self {
        let exe = exe.as_ref().to_path_buf();
        let sib = |suffix: &str| {
            let mut p = exe.clone().into_os_string();
            p.push(suffix);
            PathBuf::from(p)
        };
        Self { staged: sib(".new"), prev: sib(".prev"), marker: sib(".pending"), exe }
    }

    /// 正在运行的自己（`/proc/self/exe` 的等价物）。
    pub fn current() -> Result<Self> {
        Ok(Self::at(std::env::current_exe().context("找不到自己的路径")?))
    }
}

/// 把新二进制暂存到旁边。**先落地、后替换**：任何一步失败都不影响正在运行的那个。
///
/// 权限按 0755 设：它会成为 service 的 `ExecStart`。用一个独立文件而不是临时目录，
/// 是为了让最后的 `rename` 同目录 —— 跨设备的 `rename` 会失败，而 `/tmp` 常常是另一个文件系统。
pub fn stage(plan: &Plan, bytes: &[u8]) -> Result<()> {
    let mut f = fs::File::create(&plan.staged).with_context(|| format!("写 {:?}", plan.staged))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    set_executable(&plan.staged)?;
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).with_context(|| format!("chmod {:?}", path))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// 换上去：留一份 `.prev`，把暂存的换到位，最后落下 marker。
///
/// **顺序是有意的**：先留 `.prev`（回滚的唯一凭据），再换，最后写 marker。
/// marker 在替换**之后**写，所以"有 marker"意味着"这里换过一次、还没自证过"。
pub fn commit(plan: &Plan, from_version: &str, to_version: &str) -> Result<()> {
    if plan.prev.exists() {
        // 上一次的 `.prev` 是更早的版本；现在的自己是"上一次升级后的版本"，
        // 它才是这次要留的退路。
        fs::remove_file(&plan.prev).with_context(|| format!("删旧的 {:?}", plan.prev))?;
    }
    // `rename` 而不是 copy：同一目录下它是原子的，而且正在运行的 inode 继续有效
    // —— 这就是"替换正在运行的可执行文件"在 Linux 上安全的原因。
    fs::rename(&plan.exe, &plan.prev).with_context(|| format!("备份 {:?}", plan.exe))?;
    if let Err(e) = fs::rename(&plan.staged, &plan.exe) {
        // 换失败就把退路放回去 —— 不能留下一个没有可执行文件的机器。
        let _ = fs::rename(&plan.prev, &plan.exe);
        return Err(e).with_context(|| format!("换到 {:?}", plan.exe));
    }
    // marker 里记下**从哪来、到哪去**：远程机器上回滚之后，只有日志能告诉你发生了什么，
    // 而"从 1.1.4 回滚到 1.1.3"比"已回滚"有用得多。
    //
    // ⚠️ `to` 必须是**公告的目标版本** ✗✗ —— 它曾经写的是 `env!("CARGO_PKG_VERSION")`，
    // 也就是**此刻还在运行的旧版本**，于是日志永远是"1.1.15 → 1.1.15"；更要紧的是，
    // 启动自检没有可信的"我应该是什么版本"可比（见 `same_version`）。
    fs::write(&plan.marker, format!("pending {from_version} {to_version}\n"))
        .with_context(|| format!("写 {:?}", plan.marker))?;
    Ok(())
}

/// 换回来：把 `.prev` 放回原位并清掉 marker。自检失败时由**新**的自己调用。
pub fn rollback(plan: &Plan) -> Result<()> {
    if !plan.prev.exists() {
        anyhow::bail!("没有 {:?}，无法回滚", plan.prev);
    }
    fs::rename(&plan.prev, &plan.exe).with_context(|| format!("回滚到 {:?}", plan.exe))?;
    clear_marker(plan);
    Ok(())
}

/// 换上新二进制之后，**是不是该立刻回滚**（版本核对）。
///
/// ⚠️⚠️ 只在 **marker 是新格式**（`from != to`）时核对 ✗✗ —— 旧版本的 `commit` 写的是
/// `pending {from} {CARGO_PKG_VERSION}`，而它传的 `from` 也是自己的版本 ⇒ **旧 marker 里
/// `from == to`**，根本没有"目标版本"这一项。
///
/// 这正是 1.1.16 的那个回归：它假设 marker 一定是新格式，于是**每一台还在旧版本的机器**
/// 升上来时都会看到 `to` = 自己的旧版本、实际运行的是新版本 ⇒ 判定"不一致" ⇒ 立刻回滚，
/// 而回滚会清掉 marker ⇒ 永远升不上去。只认新格式就没事了：第一跳跳过核对（无信息可核），
/// 之后的每一跳都带着真实目标版本。
pub fn should_roll_back(from: &str, to: &str, running: &str) -> bool {
    if from == to {
        return false; // 旧格式：没有目标版本可比
    }
    !same_version(running, to)
}

/// marker 记的**目标版本**与**正在运行的版本**是否一致。
///
/// 只比规范化后的字符串（去空白、去前导 `v`）。任一边是空串时返回 `true` —— 那种情况下
/// 我们说不清，而"因为格式不同就把一次升级回滚掉"更糟。
pub fn same_version(running: &str, target: &str) -> bool {
    let norm = |s: &str| s.trim().trim_start_matches(['v', 'V']).to_owned();
    let (a, b) = (norm(running), norm(target));
    if a.is_empty() || b.is_empty() {
        return true;
    }
    a == b
}

/// 上一次替换是否还没自证过。
pub fn pending(plan: &Plan) -> bool {
    plan.marker.exists()
}

/// marker 里的 `(换下的是谁, 换上的是谁)`；格式不对时 `None`（不猜）。
pub fn marker_versions(plan: &Plan) -> Option<(String, String)> {
    let text = fs::read_to_string(&plan.marker).ok()?;
    let mut it = text.split_whitespace();
    match (it.next(), it.next(), it.next()) {
        (Some("pending"), Some(from), Some(to)) => Some((from.to_owned(), to.to_owned())),
        _ => None,
    }
}

/// 自证成功：清掉 marker（此后不再回滚）。
pub fn clear_marker(plan: &Plan) {
    let _ = fs::remove_file(&plan.marker);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个测试一个**唯一**目录。
    ///
    /// 一开始用 `SystemTime::subsec_nanos()`：macOS 上它只有微秒级，而这几条测试是**并行**跑的
    /// —— 两个测试可能撞进同一个目录、互相覆盖文件，于是出现"单独跑都过、一起跑偶尔红"的 flaky。
    /// 原子计数器没有这个问题。
    fn tmp() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "apply-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }
    fn setup() -> (PathBuf, Plan) {
        let d = tmp();
        let exe = d.join("monitor-agent");
        fs::write(&exe, b"OLD").unwrap();
        (d, Plan::at(&exe))
    }

    /// 暂存**不影响**正在运行的那个 —— 这是"先落地、后替换"的全部意义。
    #[test]
    fn staging_leaves_the_running_binary_alone() {
        let (_d, plan) = setup();
        stage(&plan, b"NEW").unwrap();
        assert_eq!(fs::read(&plan.exe).unwrap(), b"OLD", "暂存期间不能动它");
        assert_eq!(fs::read(&plan.staged).unwrap(), b"NEW");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = fs::metadata(&plan.staged).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o755, "它要成为 ExecStart，必须可执行");
        }
    }

    /// 换上去：新的是新的、退路是旧的、marker 落下了。
    #[test]
    fn commit_keeps_the_previous_and_leaves_a_marker() {
        let (_d, plan) = setup();
        stage(&plan, b"NEW").unwrap();
        commit(&plan, "1.1.3", "1.1.4").unwrap();
        assert_eq!(fs::read(&plan.exe).unwrap(), b"NEW");
        assert_eq!(fs::read(&plan.prev).unwrap(), b"OLD", "退路必须是换之前那个");
        assert!(pending(&plan), "换过之后应当有待自证的 marker");
        assert!(!plan.staged.exists(), "暂存文件已经被 rename 走了");
    }

    /// **回滚把旧的放回来，并清掉 marker**（此后不再回滚）。
    #[test]
    fn rollback_restores_the_previous_and_clears_the_marker() {
        let (_d, plan) = setup();
        stage(&plan, b"NEW").unwrap();
        commit(&plan, "1.1.3", "1.1.4").unwrap();
        rollback(&plan).unwrap();
        assert_eq!(fs::read(&plan.exe).unwrap(), b"OLD", "回滚后必须还是旧的");
        assert!(!pending(&plan), "回滚完就不该再有 marker");
        assert!(!plan.prev.exists(), "退路已经被放回原位");
    }

    /// 自证成功：清 marker，`.prev` **留着**（下一次升级还要用它）。
    #[test]
    fn clearing_the_marker_keeps_the_previous_for_next_time() {
        let (_d, plan) = setup();
        stage(&plan, b"NEW").unwrap();
        commit(&plan, "1.1.3", "1.1.4").unwrap();
        clear_marker(&plan);
        assert!(!pending(&plan));
        assert!(plan.prev.exists(), "自证通过不等于把退路删掉");
    }

    /// 连续两次升级：退路应当是**上一次换上去的那个**，而不是最老的那个。
    #[test]
    fn a_second_upgrade_keeps_the_intermediate_version_as_the_way_back() {
        let (_d, plan) = setup();
        stage(&plan, b"V2").unwrap();
        commit(&plan, "1.1.3", "1.1.4").unwrap();
        clear_marker(&plan);
        stage(&plan, b"V3").unwrap();
        commit(&plan, "1.1.3", "1.1.4").unwrap();
        assert_eq!(fs::read(&plan.exe).unwrap(), b"V3");
        assert_eq!(fs::read(&plan.prev).unwrap(), b"V2", "退路是 V2（上一个能跑的）");
    }

    /// **marker 要记下从哪来、到哪去** —— 远程机器上回滚之后，这是唯一说清"发生了什么"的东西。
    #[test]
    fn the_marker_names_both_versions() {
        let (_d, plan) = setup();
        stage(&plan, b"NEW").unwrap();
        commit(&plan, "1.1.3", "1.1.4").unwrap();
        let (from, to) = marker_versions(&plan).expect("marker 应能读出版本");
        assert_eq!(from, "1.1.3", "换下的是谁");
        // ⚠️ 换上的是**公告的目标版本**，不是"当前这个二进制"的编译版本 —— 后者是旧版本，
        // 写进去就成了"1.1.3 → 1.1.3"，而启动自检也就没有可信的"我应该是什么版本"可比。
        assert_eq!(to, "1.1.4", "换上的是公告的那个版本");
    }

    /// **旧格式的 marker 不能触发回滚** —— 这是 1.1.16 的回归。
    ///
    /// 旧 `commit` 写的 marker 里 `from == to`（两者都是它自己的版本）。1.1.16 假设 marker
    /// 一定是新格式，于是每台从旧版本升上来的机器看到 "to=旧版本、实际=新版本" ⇒ 立刻回滚，
    /// 回滚又清掉 marker ⇒ **永远升不上去**。
    #[test]
    fn a_legacy_marker_never_rolls_the_upgrade_back() {
        // 旧格式（from == to）+ 新版本正在运行 ⇒ 不回滚
        assert!(!should_roll_back("1.1.15", "1.1.15", "1.1.16"), "旧 marker 没有目标版本可比");
        // 新格式 + 确实换成了公告的那一版 ⇒ 不回滚
        assert!(!should_roll_back("1.1.15", "1.1.16", "1.1.16"));
        // 新格式 + 实际版本不是公告的那一版（降级）⇒ 回滚
        assert!(should_roll_back("1.1.15", "1.1.16", "1.1.15"), "降级必须被认出来");
    }

    /// 版本比对只做规范化：去空白、去前导 `v`；说不清时**不**判为不一致。
    #[test]
    fn versions_are_compared_after_normalising() {
        assert!(same_version("1.1.4", "1.1.4"));
        assert!(same_version("v1.1.4", "1.1.4"));
        assert!(same_version(" 1.1.4 ", "1.1.4"));
        assert!(!same_version("1.1.3", "1.1.4"), "降级必须被认出来");
        assert!(same_version("", "1.1.4"), "说不清时不判为不一致");
        assert!(same_version("1.1.4", ""), "说不清时不判为不一致");
    }

    /// 没有退路时回滚必须**报错**，而不是装作成功。
    #[test]
    fn rollback_without_a_previous_fails_loudly() {
        let (_d, plan) = setup();
        assert!(rollback(&plan).is_err());
    }
}
