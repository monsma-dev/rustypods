//! rustypods-ingress — the hostname router for `<host>.rustypods.localhost`.
#![forbid(unsafe_code)]
//!
//! Two halves: `control` holds the route table and serves the daemon's
//! snapshot pushes over a root-only UDS; `proxy` is the public HTTP(S)
//! side — plain HTTP only redirects to HTTPS, TLS terminates locally and
//! requests stream to the pod endpoint behind each host.

pub mod control;
pub mod net;
pub mod proxy;
