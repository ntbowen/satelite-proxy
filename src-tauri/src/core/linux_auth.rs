//! Linux privileged execution — file capabilities via polkit (`pkexec`).
//!
//! TUN interface creation (`TUNSETIFF`) requires `CAP_NET_ADMIN`. Rather than
//! setuid-rooting the core binary (the macOS approach), Linux grants the
//! finer-grained capability once with `setcap`:
//!
//! - The binary stays user-owned, so future core upgrades replace it freely —
//!   the new inode carries no caps, and the next TUN start re-prompts (same
//!   UX as macOS's "re-authorize after core update").
//! - `pkexec` drives polkit's GUI password dialog on GNOME/KDE; no terminal
//!   interaction is needed, matching the desktop app's expectations.
//!
//! Detection runs through `getcap` output parsing — a file either carries
//! `cap_net_admin` or not; we only ever write the `ep` (effective+permitted)
//! form, so presence alone is a reliable ownership marker.

use crate::error::{AppError, AppResult};
use std::path::Path;
use std::process::Command;

/// True when `core` already carries the cap_net_admin file capability.
///
/// `getcap` prints e.g. `/path/to/sing-box cap_net_admin=ep` (libcap ≥ 2.42)
/// or the legacy `cap_net_admin+ep` form — both lowercase-match the needle.
pub fn core_has_cap_net_admin(core: &Path) -> bool {
    Command::new("getcap")
        .arg(core)
        .output()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout).to_lowercase();
            getcap_output_has_cap_net_admin(&out)
        })
        .unwrap_or(false)
}

fn getcap_output_has_cap_net_admin(out: &str) -> bool {
    out.lines().any(|l| l.contains("cap_net_admin"))
}

/// Ensure the core binary has `cap_net_admin+ep` so TUN starts without root.
///
/// Runs `pkexec setcap` when the capability is missing; polkit pops a GUI
/// authentication dialog once. Errors surface verbatim so callers can append
/// the platform guidance (`map_tun_permission_hint`).
pub fn ensure_core_cap_net_admin(core: &Path) -> AppResult<()> {
    if !core.is_file() {
        return Err(AppError::Core(format!(
            "core binary not found for setcap: {}",
            core.display()
        )));
    }
    if core_has_cap_net_admin(core) {
        return Ok(());
    }

    let core_name = core
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "core".into());
    crate::app_log::info(
        "auth",
        format!(
            "authorizing cap_net_admin on {core_name} (polkit): {}",
            core.display()
        ),
    );

    let out = Command::new("pkexec")
        .args(["setcap", "cap_net_admin+ep"])
        .arg(core)
        .output()
        .map_err(|e| {
            AppError::Core(format!(
                "无法执行 pkexec（polkit 授权工具缺失？）: {e}。\n\
                 可手动授权：sudo setcap cap_net_admin+ep '{}'",
                core.display()
            ))
        })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // pkexec exits 126 when the dialog is dismissed/cancelled.
        if out.status.code() == Some(126) {
            return Err(AppError::Core(
                "已取消管理员授权。TUN 模式需要一次性授权内核（cap_net_admin）。".into(),
            ));
        }
        return Err(AppError::Core(if stderr.is_empty() {
            format!("为 {core_name} 设置 cap_net_admin 失败（无错误详情）")
        } else {
            format!("为 {core_name} 设置 cap_net_admin 失败:\n{stderr}")
        }));
    }

    if !core_has_cap_net_admin(core) {
        return Err(AppError::Core(format!(
            "管理员提权已执行，但 {core_name} 仍未携带 cap_net_admin。\n\
             可手动检查：getcap '{}'",
            core.display()
        )));
    }

    crate::app_log::info("auth", format!("{core_name} cap_net_admin ok"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getcap_parse_matches_new_and_legacy_forms() {
        assert!(getcap_output_has_cap_net_admin(
            "/home/u/bin/sing-box cap_net_admin=ep\n"
        ));
        assert!(getcap_output_has_cap_net_admin(
            "/home/u/bin/mihomo cap_net_admin+ep\n"
        ));
        assert!(!getcap_output_has_cap_net_admin("/home/u/bin/sing-box\n"));
        assert!(!getcap_output_has_cap_net_admin(""));
    }

    #[test]
    fn plain_file_has_no_cap() {
        let dir = std::env::temp_dir();
        let f = dir.join("satelite-linux-auth-test-plain");
        std::fs::write(&f, b"x").unwrap();
        assert!(!core_has_cap_net_admin(&f));
        let _ = std::fs::remove_file(&f);
    }
}
