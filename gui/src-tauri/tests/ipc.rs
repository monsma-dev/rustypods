//! End-to-end IPC test: builds the app on Tauri's MockRuntime and invokes the
//! real commands against a running rustypodsd on /run/rustypods/daemon.sock.
//! Requires the daemon to be up and a pod named `dev` to exist.

use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeResponseBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::WebviewWindow;

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
