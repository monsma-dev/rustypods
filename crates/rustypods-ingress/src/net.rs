//! Listener setup. `[::]` must accept IPv4 clients too — Linux defaults
//! IPV6_V6ONLY=0, but the sysctl is user-tunable, so set it explicitly
//! before bind instead of inheriting whatever the host happens to use.

use std::io;
use std::net::SocketAddr;

/// Bind+listen a TCP socket with explicit family semantics: v6 sockets
/// get `IPV6_V6ONLY` cleared (dual-stack), v4 stays v4. Reuseaddr is
/// always set — restarts shouldn't wait out TIME_WAIT.
pub fn dual_stack_listener(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => {
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?
        }
        SocketAddr::V6(_) => {
            let s = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
            s.set_only_v6(false)?;
            s
        }
    };
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    tokio::net::TcpListener::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `[::]` listener must accept BOTH families on Linux.
    #[tokio::test]
    async fn wildcard_v6_accepts_v4_and_v6() {
        let listener = dual_stack_listener("[::]:0".parse().unwrap()).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (a4, a6) = tokio::join!(
            tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")),
            tokio::net::TcpStream::connect(format!("[::1]:{port}")),
        );
        a4.expect("v4-mapped connect to [::] listener failed");
        a6.expect("v6 connect to [::] listener failed");
        // Drain the pending accepts so nothing lingers.
        let _ = listener.accept().await;
        let _ = listener.accept().await;
    }

    #[tokio::test]
    async fn v4_listener_still_works() {
        let listener = dual_stack_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
    }
}
