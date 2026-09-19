//! End-to-end IPC test: builds the app on Tauri's MockRuntime and invokes the
//! real commands against a running rustypodsd on /run/rustypods/daemon.sock.
//! Requires the daemon to be up and a pod named `dev` to exist.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeResponseBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{Listener, Manager, WebviewWindow};

fn webview() -> WebviewWindow<tauri::test::MockRuntime> {
    let app = rustypods_gui_lib::app_builder(mock_builder())
        .build(mock_context(noop_assets()))
        .expect("build mock app");
    tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("mock webview")
}

fn invoke(
    wv: &WebviewWindow<tauri::test::MockRuntime>,
    cmd: &str,
    args: Value,
) -> Result<Value, Value> {
    get_ipc_response(
        wv,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: "tauri://localhost".parse().unwrap(),
            body: args.into(),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
    .map(|b| match b {
        InvokeResponseBody::Json(s) => serde_json::from_str(&s).unwrap(),
        InvokeResponseBody::Raw(_) => panic!("unexpected raw response"),
    })
}

#[test]
fn pods_lifecycle_via_ipc() {
    let wv = webview();

    let pods = invoke(&wv, "get_pods", json!({})).expect("get_pods failed");
    let pods = pods.as_array().unwrap();
    assert!(pods.iter().any(|p| p["name"] == "dev"), "no dev pod: {pods:?}");

    // state is the proto enum: 2 = RUNNING, 3 = STOPPED (POD_STATE_*).
    let stopped = invoke(&wv, "stop_pod", json!({"name": "dev"})).expect("stop failed");
    assert_eq!(stopped["state"], 3);

    let pods = invoke(&wv, "get_pods", json!({})).unwrap();
    let dev = pods
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "dev")
        .unwrap();
    assert_eq!(dev["state"], 3);
    assert!(dev["binds"].is_array(), "dev.binds should be an array: {dev:?}");

    let started = invoke(&wv, "start_pod", json!({"name": "dev"})).expect("start failed");
    assert_eq!(started["state"], 2);
    assert!(started["leaderPid"].as_u64().unwrap() > 0);

    // Live config update: new limits + a port mapping, hot-applied.
    let updated = invoke(
        &wv,
        "update_pod_config",
        json!({
            "name": "dev",
            "memoryHighBytes": 8u64 << 30,
            "memoryMaxBytes": 9u64 << 30,
            "cpuQuotaPercent": 200,
            "storageMaxBytes": 15u64 << 30,
            "ports": ["18099:22/tcp"],
        }),
    )
    .expect("update_pod_config failed");
    assert_eq!(updated["limits"]["memoryHighBytes"], 8u64 << 30);
    assert_eq!(updated["limits"]["cpuQuotaPercent"], 200);
    assert_eq!(updated["ports"], json!(["18099:22/tcp"]));

    // Restore dev's original config.
    let restored = invoke(
        &wv,
        "update_pod_config",
        json!({
            "name": "dev",
            "memoryHighBytes": 10u64 << 30,
            "memoryMaxBytes": 12u64 << 30,
            "cpuQuotaPercent": 400,
            "storageMaxBytes": 20u64 << 30,
            "ports": Vec::<String>::new(),
        }),
    )
    .expect("restore failed");
    assert_eq!(restored["ports"], json!([]));

    let info = invoke(&wv, "get_daemon_info", json!({})).expect("ping failed");
    assert_eq!(info["storageDriver"], "btrfs");
}

/// Wizard round-trip: create_pod → start_pod → stop_pod → destroy_pod for a
/// throwaway pod. Requires the daemon + an `arch-base` image; nspawn boot
/// takes a few seconds.
#[test]
fn create_wizard_cycle_via_ipc() {
    let wv = webview();

    let created = invoke(
        &wv,
        "create_pod",
        json!({
            "name": "wiztest",
            "image": "arch-base",
            "memoryHighBytes": 512u64 << 20,
            "memoryMaxBytes": 0,
            "cpuQuotaPercent": 0,
            "storageMaxBytes": 0,
            "ports": Vec::<String>::new(),
            "binds": Vec::<String>::new(),
            "desktop": false,
        }),
    )
    .expect("create_pod failed");
    assert_eq!(created["name"], "wiztest");
    assert_eq!(created["limits"]["memoryHighBytes"], 512u64 << 20);
    // hermetic: desktop=false → private_users on
    assert_eq!(created["privateUsers"], true);

    let started = invoke(&wv, "start_pod", json!({"name": "wiztest"}))
        .expect("start failed");
    assert_eq!(started["state"], 2);
    assert!(started["leaderPid"].as_u64().unwrap() > 0);

    // start returns at machined registration — the pod's systemd is still
    // booting. SIGRTMIN+3 mid-boot wedges systemd-shutdown (a hung
    // (sd-chown) job even delays TerminateMachine's SIGKILL), so let the
    // pod reach running state before exercising the stop path.
    std::thread::sleep(std::time::Duration::from_secs(10));

    let stopped = invoke(&wv, "stop_pod", json!({"name": "wiztest"}))
        .expect("stop failed");
    assert_eq!(stopped["state"], 3);

    invoke(&wv, "destroy_pod", json!({"name": "wiztest"})).expect("destroy failed");
    let pods = invoke(&wv, "get_pods", json!({})).unwrap();
    assert!(
        !pods.as_array().unwrap().iter().any(|p| p["name"] == "wiztest"),
        "wiztest still listed: {pods:?}"
    );
}

/// Stack round-trip: apply_stack wires the shared netns + veth as root and
/// clones the member rootfs; destroy_stack tears both down again.
/// Requires the daemon + an `arch-base` image.
#[test]
fn stack_apply_destroy_via_ipc() {
    let wv = webview();

    let toml = r#"
name = "ipcstack"

[pods.a]
image = "arch-base"
"#;
    let res =
        invoke(&wv, "apply_stack", json!({ "toml": toml })).expect("apply_stack failed");
    assert_eq!(res["name"], "ipcstack");
    let pods = res["pods"].as_array().unwrap();
    assert_eq!(pods.len(), 1, "expected 1 member: {res:?}");
    assert_eq!(pods[0]["name"], "ipcstack-a");
    assert_eq!(pods[0]["stack"], "ipcstack");

    invoke(&wv, "destroy_stack", json!({ "name": "ipcstack" }))
        .expect("destroy_stack failed");
    let pods = invoke(&wv, "get_pods", json!({})).unwrap();
    assert!(
        !pods
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "ipcstack-a"),
        "ipcstack-a still listed: {pods:?}"
    );
}

/// PTY bridge round-trip: open_pty spawns a login shell in the `dev` pod,
/// stdout chunks arrive as `pty-out-dev` events, write_pty feeds stdin, and
/// the shell's echo output comes back through the same event. Requires the
/// daemon + a running `dev` pod.
#[test]
fn pty_session_via_ipc() {
    let wv = webview();

    // Make sure dev is running (the lifecycle test may run concurrently).
    let _ = invoke(&wv, "start_pod", json!({"name": "dev"}));

    // (Verified during dev: app.emit reaches listen_any handlers on the
    // MockRuntime — pod-metrics events via watch_metrics arrive fine.)

    // pty-out-<pod> payloads are Vec<u8> serialized as JSON int arrays —
    // accumulate them here from the mock runtime's event dispatch.
    let out = Arc::new(Mutex::new(Vec::<u8>::new()));
    let out2 = Arc::clone(&out);
    wv.app_handle().listen_any("pty-out-dev", move |ev| {
        if let Ok(bytes) = serde_json::from_str::<Vec<u8>>(ev.payload()) {
            out2.lock().unwrap().extend(bytes);
        }
    });
    let exits = Arc::new(Mutex::new(Vec::<i32>::new()));
    let exits2 = Arc::clone(&exits);
    wv.app_handle().listen_any("pty-exit-dev", move |ev| {
        exits2
            .lock()
            .unwrap()
            .push(serde_json::from_str::<i32>(ev.payload()).unwrap_or(-999));
    });

    // pods_lifecycle_via_ipc may concurrently stop/start dev — retry open_pty
    // while it settles. Re-opening replaces the previous session, so retries
    // are safe.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut opened = false;
    while Instant::now() < deadline {
        if invoke(&wv, "open_pty", json!({"pod": "dev", "cols": 80, "rows": 24})).is_ok() {
            opened = true;
            break;
        }
        let _ = invoke(&wv, "start_pod", json!({"name": "dev"}));
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(opened, "open_pty never succeeded — is dev running?");

    // The login shell should emit a prompt within a few seconds.
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline && out.lock().unwrap().is_empty() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !out.lock().unwrap().is_empty(),
        "no pty-out-dev events — shell never wrote to the pty (exit codes seen: {:?})",
        exits.lock().unwrap()
    );

    invoke(
        &wv,
        "write_pty",
        json!({"pod": "dev", "data": b"echo RP_OK\n".to_vec()}),
    )
    .expect("write_pty failed");

    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        let buf = out.lock().unwrap().clone();
        if buf.windows(5).any(|w| w == b"RP_OK") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    invoke(&wv, "close_pty", json!({"pod": "dev"})).expect("close_pty failed");

    let buf = out.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("RP_OK"),
        "echo output never arrived over pty-out-dev: {text:?}"
    );
}
