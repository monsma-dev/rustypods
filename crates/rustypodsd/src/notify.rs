//! systemd `Type=notify` readiness without libsystemd.
//!
//! `systemctl restart rustypodsd` returns only after `READY=1`, so a CLI
//! call straight after it no longer races the socket bind.

use std::ffi::OsString;
use std::os::unix::net::UnixDatagram;

#[derive(Debug, Clone, Default)]
pub struct Notifier(Option<OsString>);

impl Notifier {
    /// Takes `NOTIFY_SOCKET` out of the environment so nspawn and every
    /// other child do not inherit it: nspawn would otherwise send its own
    /// READY/STATUS to this unit's socket. Call before any thread exists —
    /// `remove_var` races concurrent `getenv`.
    pub fn take_from_env() -> Self {
        let sock = std::env::var_os("NOTIFY_SOCKET");
        if sock.is_some() {
            std::env::remove_var("NOTIFY_SOCKET");
        }
        Self(sock)
    }

    pub fn ready(&self) {
        self.send("READY=1");
    }

    pub fn stopping(&self) {
        self.send("STOPPING=1");
    }

    fn send(&self, msg: &str) {
        let Some(path) = &self.0 else { return };
        if let Err(e) = send_to(path, msg.as_bytes()) {
            tracing::warn!("sd_notify {msg}: {e}");
        }
    }
}

fn send_to(path: &OsString, msg: &[u8]) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    let sock = UnixDatagram::unbound()?;
    let bytes = path.as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
        sock.send_to_addr(msg, &addr)?;
    } else {
        sock.send_to(msg, std::path::Path::new(path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_to_a_path_socket() {
        let dir = std::env::temp_dir().join(format!("rp-notify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify.sock");
        let rx = UnixDatagram::bind(&path).unwrap();
        Notifier(Some(path.clone().into_os_string())).ready();
        let mut buf = [0u8; 32];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sends_to_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("rp-notify-test-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let rx = UnixDatagram::bind_addr(&addr).unwrap();
        Notifier(Some(format!("@{name}").into())).stopping();
        let mut buf = [0u8; 32];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1");
    }

    #[test]
    fn absent_socket_is_a_no_op() {
        Notifier::default().ready();
    }
}
