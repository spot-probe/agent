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
pub fn commit(plan: &Plan, from_version: &str) -> Result<()> {
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
    // 而"从 1.1.4 回滚到 1.1.3"比"已回滚"有用得多。新版本号取自编译进去的常量 ——
    // 此刻运行着的就是它。
    fs::write(&plan.marker, format!("pending {from_version} {}\n", env!("CARGO_PKG_VERSION")))
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
        commit(&plan, "1.1.3").unwrap();
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
        commit(&plan, "1.1.3").unwrap();
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
        commit(&plan, "1.1.3").unwrap();
        clear_marker(&plan);
        assert!(!pending(&plan));
        assert!(plan.prev.exists(), "自证通过不等于把退路删掉");
    }

    /// 连续两次升级：退路应当是**上一次换上去的那个**，而不是最老的那个。
    #[test]
    fn a_second_upgrade_keeps_the_intermediate_version_as_the_way_back() {
        let (_d, plan) = setup();
        stage(&plan, b"V2").unwrap();
        commit(&plan, "1.1.3").unwrap();
        clear_marker(&plan);
        stage(&plan, b"V3").unwrap();
        commit(&plan, "1.1.3").unwrap();
        assert_eq!(fs::read(&plan.exe).unwrap(), b"V3");
        assert_eq!(fs::read(&plan.prev).unwrap(), b"V2", "退路是 V2（上一个能跑的）");
    }

    /// **marker 要记下从哪来、到哪去** —— 远程机器上回滚之后，这是唯一说清"发生了什么"的东西。
    #[test]
    fn the_marker_names_both_versions() {
        let (_d, plan) = setup();
        stage(&plan, b"NEW").unwrap();
        commit(&plan, "1.1.3").unwrap();
        let (from, to) = marker_versions(&plan).expect("marker 应能读出版本");
        assert_eq!(from, "1.1.3", "换下的是谁");
        assert_eq!(to, env!("CARGO_PKG_VERSION"), "换上的是谁（就是当前这个二进制）");
    }

    /// 没有退路时回滚必须**报错**，而不是装作成功。
    #[test]
    fn rollback_without_a_previous_fails_loudly() {
        let (_d, plan) = setup();
        assert!(rollback(&plan).is_err());
    }
}
