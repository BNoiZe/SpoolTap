#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! SpoolTap: tray app. Tap an NFC tag on a PC/SC reader -> report the UID to Spoolman
//! (/api/v1/tag/scan) -> show the spool, or create/link one for an unknown tag.

mod cfs;
mod reader;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::image::Image;
use tauri::menu::{AboutMetadata, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, WebviewUrl, WebviewWindowBuilder, WindowEvent, Wry};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_opener::OpenerExt;

#[derive(Serialize, Deserialize, Clone, Default)]
struct Settings {
    base_url: String,
    reader: Option<String>,
    #[serde(default)]
    login_asked: bool,
}

/// "Add a second tag": the next new tag on the reader joins this spool with the same CFS record.
#[derive(Clone, Deserialize)]
struct CfsCopy {
    material_id: String,
    color_hex: String,
    meters: i64,
}

#[derive(Clone)]
struct CopyJob {
    spool_id: i64,
    source_uid: String,
    cfs: Option<CfsCopy>,
}

struct AppState {
    settings: Mutex<Settings>,
    wanted_reader: Arc<Mutex<Option<String>>>,
    card_busy: Arc<AtomicBool>,
    /// (reader, uid) of the tag lying on the reader
    current: Mutex<Option<(String, String)>>,
    /// what the panel window shows: {kind: "info"|"link", uid, spool?}
    panel: Mutex<Value>,
    panel_busy: AtomicBool,
    copy: Mutex<Option<CopyJob>>,
    status: Mutex<Option<MenuItem<Wry>>>,
    tray_menu: Mutex<Option<Menu<Wry>>>,
    /// latest Spoolman version while an update is offered in the tray menu
    update_shown: Mutex<Option<String>>,
    http: reqwest::Client,
}

fn state(app: &AppHandle) -> tauri::State<'_, AppState> {
    app.state::<AppState>()
}

fn settings_path(app: &AppHandle) -> PathBuf {
    app.path().app_config_dir().unwrap_or_default().join("settings.json")
}

fn load_settings(app: &AppHandle) -> Option<Settings> {
    serde_json::from_slice(&std::fs::read(settings_path(app)).ok()?).ok()
}

fn store_settings(app: &AppHandle, s: &Settings) {
    let p = settings_path(app);
    let _ = std::fs::create_dir_all(p.parent().unwrap());
    let _ = std::fs::write(p, serde_json::to_vec_pretty(s).unwrap());
}

/// Settings of the former Swift build (UserDefaults domain local.spooltap), so updating keeps the setup.
fn legacy_settings() -> Option<Settings> {
    #[cfg(target_os = "macos")]
    {
        let read = |k: &str| {
            let o = std::process::Command::new("defaults").args(["read", "local.spooltap", k]).output().ok()?;
            o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        };
        return read("baseURL").map(|base_url| Settings { base_url, reader: read("reader"), login_asked: false });
    }
    #[allow(unreachable_code)]
    None
}

fn base_url(app: &AppHandle) -> String {
    state(app).settings.lock().unwrap().base_url.trim_end_matches('/').to_string()
}

fn set_status(app: &AppHandle, text: &str) {
    if let Some(item) = state(app).status.lock().unwrap().as_ref() {
        let _ = item.set_text(text);
    }
}

fn reader_id() -> String {
    let host = gethostname::gethostname().to_string_lossy().trim_end_matches(".local").to_string();
    let os = if cfg!(target_os = "macos") { "mac" } else { std::env::consts::OS };
    format!("{os}-{host}").chars().map(|c| if c.is_ascii_alphanumeric() || "._:-".contains(c) { c } else { '-' }).take(64).collect()
}

// ---------- Spoolman API ----------

#[derive(Serialize)]
struct ApiResult {
    code: u16,
    json: Value,
}

async fn spoolman(app: &AppHandle, method: &str, path: &str, query: Option<HashMap<String, String>>, body: Option<Value>) -> Result<ApiResult, String> {
    let url = format!("{}/api/v1{}", base_url(app), path);
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let mut req = state(app).http.request(method, &url);
    if let Some(q) = query {
        req = req.query(&q);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.map_err(|e| format!("Spoolman nicht erreichbar: {e}"))?;
    let code = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(Value::Null);
    Ok(ApiResult { code, json })
}

#[tauri::command]
async fn api(app: AppHandle, method: String, path: String, query: Option<HashMap<String, String>>, body: Option<Value>) -> Result<ApiResult, String> {
    spoolman(&app, &method, &path, query, body).await
}

#[derive(Serialize, Default)]
struct Connection {
    ok: bool,
    message: String,
    version: Option<String>,
    latest: Option<String>,
    update_available: bool,
}

/// GET <url>/api/v1/info. Spoolman itself tracks the latest release (latest_version, update_available).
async fn spoolman_info(app: &AppHandle, base: &str) -> Connection {
    let url = format!("{}/api/v1/info", base.trim().trim_end_matches('/'));
    let fail = |message: String| Connection { message, ..Default::default() };
    match state(app).http.get(&url).send().await {
        Ok(r) if r.status().is_success() => match r.json::<Value>().await {
            Ok(v) if v["version"].is_string() => Connection {
                ok: true,
                message: format!("Spoolman {}", v["version"].as_str().unwrap()),
                version: v["version"].as_str().map(str::to_string),
                latest: v["latest_version"].as_str().map(str::to_string),
                update_available: v["update_available"].as_bool().unwrap_or(false),
            },
            _ => fail("Antwort ist kein Spoolman".into()),
        },
        Ok(r) => fail(format!("HTTP {} – ist das Spoolman?", r.status().as_u16())),
        Err(e) => fail(if e.is_builder() { "Ungültige URL".into() } else { e.to_string() }),
    }
}

#[tauri::command]
async fn test_connection(app: AppHandle, url: String) -> Connection {
    let c = spoolman_info(&app, &url).await;
    if c.ok {
        show_update(&app, c.update_available.then(|| c.latest.clone()).flatten());
    }
    c
}

fn release_url(version: &str) -> String {
    format!("https://github.com/Donkie/Spoolman/releases/tag/v{}", version.trim_start_matches('v'))
}

#[tauri::command]
fn open_release_notes(app: AppHandle, version: String) {
    let _ = app.opener().open_url(release_url(&version), None::<&str>);
}

/// Add/remove the "Spoolman x.y verfügbar…" item at the top of the tray menu.
fn show_update(app: &AppHandle, latest: Option<String>) {
    let st = state(app);
    let mut shown = st.update_shown.lock().unwrap();
    if *shown == latest {
        return;
    }
    let Some(menu) = st.tray_menu.lock().unwrap().clone() else { return };
    if shown.is_some() {
        let _ = menu.remove_at(0); // item
        let _ = menu.remove_at(0); // its separator
    }
    if let Some(v) = &latest {
        if let Ok(item) = MenuItem::with_id(app, "update", format!("Spoolman {v} verfügbar…"), true, None::<&str>) {
            let _ = menu.insert(&item, 0);
            if let Ok(sep) = PredefinedMenuItem::separator(app) {
                let _ = menu.insert(&sep, 1);
            }
        }
    }
    *shown = latest;
}

/// Check at start and every 6 hours.
fn spawn_update_check(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let c = spoolman_info(&app, &base_url(&app)).await;
            if c.ok {
                show_update(&app, c.update_available.then_some(c.latest).flatten());
            }
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600 - 5)).await;
        }
    });
}

// ---------- windows ----------

/// Exact center of the work area of the monitor the mouse is on.
fn center_on_cursor_monitor(app: &AppHandle, w: &tauri::WebviewWindow) {
    let monitor = app
        .cursor_position()
        .ok()
        .and_then(|p| app.monitor_from_point(p.x, p.y).ok().flatten())
        .or_else(|| w.current_monitor().ok().flatten());
    let (Some(m), Ok(size)) = (monitor, w.outer_size()) else { return };
    let area = m.work_area();
    let x = area.position.x + (area.size.width as i32 - size.width as i32) / 2;
    let y = area.position.y + (area.size.height as i32 - size.height as i32) / 2;
    let _ = w.set_position(PhysicalPosition::new(x, y));
}

fn show_window(app: &AppHandle, label: &str, page: &str, title: &str, width: f64, height: f64) {
    let w = match app.get_webview_window(label) {
        Some(w) => {
            let _ = w.set_title(title);
            let _ = w.eval("location.reload()");
            w
        }
        None => match WebviewWindowBuilder::new(app, label, WebviewUrl::App(page.into()))
            .title(title)
            .inner_size(width, height)
            .resizable(false)
            .minimizable(false)
            .maximizable(false)
            .always_on_top(true)
            .visible(false)
            .build()
        {
            Ok(w) => {
                if label == "panel" {
                    let h = app.clone();
                    w.on_window_event(move |e| {
                        if matches!(e, WindowEvent::Destroyed) {
                            disarm(&h); // closing the window ends "add a second tag"
                        }
                    });
                }
                w
            }
            Err(e) => return set_status(app, &format!("Fenster-Fehler: {e}")),
        },
    };
    // Logical points: the scale factor changes when the window lands on another monitor (Retina vs. 1x).
    let _ = w.set_size(LogicalSize::new(width, height));
    center_on_cursor_monitor(app, &w);
    let _ = w.show();
    let _ = w.set_focus();
}

fn open_panel(app: &AppHandle, panel: Value) {
    let (title, w, h) = if panel["kind"] == "link" {
        ("SpoolTap – Tag verknüpfen".to_string(), 560.0, 640.0)
    } else {
        (format!("SpoolTap – Tag {}", panel["uid"].as_str().unwrap_or("")), 480.0, 360.0)
    };
    *state(app).panel.lock().unwrap() = panel;
    state(app).panel_busy.store(false, Ordering::SeqCst);
    show_window(app, "panel", "panel.html", &title, w, h);
}

fn close_panel_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("panel") {
        let _ = w.close();
    }
}

fn open_settings(app: &AppHandle) {
    show_window(app, "settings", "settings.html", "Einstellungen", 480.0, 240.0);
}

fn open_spoolman_path(app: &AppHandle, path: &str) {
    let _ = app.opener().open_url(format!("{}{}", base_url(app), path), None::<&str>);
}

// ---------- commands for the UI ----------

#[tauri::command]
fn get_panel(app: AppHandle) -> Value {
    state(&app).panel.lock().unwrap().clone()
}

#[tauri::command]
fn set_panel_busy(app: AppHandle, busy: bool) {
    state(&app).panel_busy.store(busy, Ordering::SeqCst);
}

#[tauri::command]
fn close_panel(app: AppHandle) {
    close_panel_window(&app);
}

#[tauri::command]
fn fit_panel(window: tauri::WebviewWindow, app: AppHandle, width: f64, height: f64) {
    let _ = window.set_size(LogicalSize::new(width, height));
    center_on_cursor_monitor(&app, &window);
}

#[tauri::command]
fn open_spoolman(app: AppHandle, path: Option<String>) {
    open_spoolman_path(&app, path.as_deref().unwrap_or("/"));
}

#[tauri::command]
fn show_info(app: AppHandle, uid: String, spool: Value) {
    set_status(&app, &format!("Tag {uid} → Spule #{} verknüpft", spool["id"]));
    open_panel(&app, json!({ "kind": "info", "uid": uid, "spool": spool }));
}

fn disarm(app: &AppHandle) {
    let st = state(app);
    if st.copy.lock().unwrap().take().is_some() {
        st.panel_busy.store(false, Ordering::SeqCst);
    }
}

#[tauri::command]
fn arm_copy(app: AppHandle, spool_id: i64, source_uid: String, cfs: Option<CfsCopy>) {
    let st = state(&app);
    *st.copy.lock().unwrap() = Some(CopyJob { spool_id, source_uid, cfs });
    st.panel_busy.store(true, Ordering::SeqCst); // lifting the source tag must not close the window
    set_status(&app, &format!("Neuen Tag für Spule #{spool_id} auflegen…"));
}

#[tauri::command]
fn disarm_copy(app: AppHandle) {
    disarm(&app);
}

#[tauri::command]
fn set_status_text(app: AppHandle, text: String) {
    set_status(&app, &text);
}

#[derive(Serialize)]
struct SettingsView {
    base_url: String,
    reader: Option<String>,
    readers: Vec<String>,
    autostart: bool,
}

#[tauri::command]
fn get_settings(app: AppHandle) -> SettingsView {
    let s = state(&app).settings.lock().unwrap().clone();
    let autostart = app.autolaunch().is_enabled().unwrap_or(false);
    SettingsView { base_url: s.base_url, reader: s.reader, readers: reader::list(), autostart }
}

#[tauri::command]
fn save_settings(app: AppHandle, base_url: String, reader: Option<String>, autostart: bool) -> Result<(), String> {
    let al = app.autolaunch();
    if al.is_enabled().unwrap_or(false) != autostart {
        if autostart { al.enable() } else { al.disable() }.map_err(|e| format!("Autostart: {e}"))?;
    }
    let st = state(&app);
    let mut s = st.settings.lock().unwrap();
    s.base_url = base_url.trim().trim_end_matches('/').to_string();
    s.reader = reader.filter(|r| !r.is_empty());
    *st.wanted_reader.lock().unwrap() = s.reader.clone();
    store_settings(&app, &s);
    Ok(())
}

// ---------- CFS ----------

#[derive(Serialize)]
struct Material {
    id: &'static str,
    brand: &'static str,
    name: &'static str,
}

#[tauri::command]
fn cfs_materials() -> Vec<Material> {
    cfs::MATERIALS.iter().map(|m| Material { id: m.0, brand: m.1, name: m.2 }).collect()
}

#[tauri::command]
fn cfs_suggest(vendor: String, name: String, material: String) -> String {
    cfs::suggest(&vendor, &name, &material).to_string()
}

/// Run a CFS operation on the tag `uid`, which must still be on the reader.
async fn on_tag<T: Send + 'static>(
    app: &AppHandle,
    uid: &str,
    op: impl FnOnce(&reader::Tx, &[u8]) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let reader = match state(app).current.lock().unwrap().clone() {
        Some((r, u)) if u == uid => r,
        _ => return Err(format!("Tag {uid} auf den Reader legen.")),
    };
    let busy = state(app).card_busy.clone();
    let uid = uid.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        reader::with_card(&reader, &uid, &busy, |tx| op(&reader::Tx(tx), &cfs::hex_bytes(&uid)))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn cfs_read(app: AppHandle, uid: String) -> Result<Option<cfs::CfsInfo>, String> {
    on_tag(&app, &uid, |c, u| cfs::read(c, u)).await
}

#[tauri::command]
async fn cfs_wipe(app: AppHandle, uid: String) -> Result<(), String> {
    on_tag(&app, &uid, |c, u| cfs::wipe(c, u)).await
}

#[tauri::command]
async fn cfs_write(app: AppHandle, uid: String, material_id: String, color_hex: String, weight: f64, serial: u32) -> Result<(), String> {
    let text = cfs::payload(&material_id, &color_hex, weight, serial);
    on_tag(&app, &uid, move |c, u| cfs::write(c, u, &text)).await
}

// ---------- tag events ----------

/// Copy mode: link the new tag `uid` to the job's spool and give it the same CFS record.
async fn copy_to(app: AppHandle, reader: String, uid: String, job: CopyJob) {
    let fail = |msg: String| {
        set_status(&app, &msg);
        let _ = app.emit_to("panel", "copy-status", json!({ "error": msg }));
    };
    set_status(&app, &format!("Tag {uid} – füge zu Spule #{} hinzu…", job.spool_id));
    let scan = json!({ "uid": uid, "reader_id": reader_id(), "name": "SpoolTap" });
    let already = match spoolman(&app, "POST", "/tag/scan", None, Some(scan)).await {
        Ok(r) if r.code == 200 => match (r.json["matched_spool_id"].as_i64(), r.json["matched_filament_id"].as_i64()) {
            (Some(id), _) if id == job.spool_id => true,
            (Some(id), _) => return fail(format!("Tag {uid} gehört schon zu Spule #{id} – anderen Tag auflegen.")),
            (_, Some(id)) => return fail(format!("Tag {uid} gehört schon zu Filament #{id} – anderen Tag auflegen.")),
            _ => false,
        },
        Ok(r) => return fail(format!("Spoolman: HTTP {}", r.code)),
        Err(e) => return fail(e),
    };
    if let (Some(c), true) = (&job.cfs, uid.len() == 8) {
        let text = cfs::payload_meters(&c.material_id, &c.color_hex, c.meters, job.spool_id as u32);
        let (busy, r, u) = (state(&app).card_busy.clone(), reader.clone(), uid.clone());
        let written = tauri::async_runtime::spawn_blocking(move || {
            reader::with_card(&r, &u, &busy, |tx| cfs::write(&reader::Tx(tx), &cfs::hex_bytes(&u), &text))
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
        if let Err(e) = written {
            return fail(format!("CFS-Daten nicht geschrieben: {e}"));
        }
    }
    if !already {
        match spoolman(&app, "POST", &format!("/spool/{}/tag", job.spool_id), None, Some(json!({ "uid": uid }))).await {
            Ok(r) if r.code == 200 || r.code == 201 => {}
            Ok(r) => return fail(format!("Verknüpfen fehlgeschlagen: {}", r.json["message"].as_str().unwrap_or(&format!("HTTP {}", r.code)))),
            Err(e) => return fail(e),
        }
    }
    let spool = match spoolman(&app, "GET", &format!("/spool/{}", job.spool_id), None, None).await {
        Ok(r) if r.code == 200 => r.json,
        _ => json!({ "id": job.spool_id }),
    };
    *state(&app).copy.lock().unwrap() = None;
    set_status(&app, &format!("Tag {uid} → Spule #{} (zusätzlicher Tag)", job.spool_id));
    open_panel(&app, json!({ "kind": "info", "uid": uid, "spool": spool }));
}

async fn on_present(app: AppHandle, reader: String, uid: String) {
    *state(&app).current.lock().unwrap() = Some((reader.clone(), uid.clone()));
    let job = state(&app).copy.lock().unwrap().clone();
    if let Some(job) = job {
        if uid != job.source_uid {
            return copy_to(app, reader, uid, job).await;
        }
        return; // the source tag put back: keep waiting for a new one
    }
    set_status(&app, &format!("Tag {uid} – frage Spoolman…"));
    let body = json!({ "uid": uid, "reader_id": reader_id(), "name": "SpoolTap" });
    match spoolman(&app, "POST", "/tag/scan", None, Some(body)).await {
        Ok(r) if r.code == 200 => {
            if let Some(id) = r.json["matched_spool_id"].as_i64() {
                set_status(&app, &format!("Tag {uid} → Spule #{id}"));
                let spool = if r.json["spool"].is_object() { r.json["spool"].clone() } else { json!({ "id": id }) };
                open_panel(&app, json!({ "kind": "info", "uid": uid, "spool": spool }));
            } else if let Some(id) = r.json["matched_filament_id"].as_i64() {
                set_status(&app, &format!("Tag {uid} → Filament #{id}"));
                open_spoolman_path(&app, &format!("/filament/show/{id}"));
            } else {
                set_status(&app, &format!("Tag {uid} unbekannt – Spule wählen"));
                open_panel(&app, json!({ "kind": "link", "uid": uid }));
            }
        }
        Ok(r) => set_status(&app, &format!("Spoolman: HTTP {}", r.code)),
        Err(e) => set_status(&app, &e),
    }
}

fn on_removed(app: &AppHandle) {
    let st = state(app);
    *st.current.lock().unwrap() = None;
    if !st.panel_busy.load(Ordering::SeqCst) {
        close_panel_window(app); // tag lifted: its window is done
    }
}

// ---------- tray ----------

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Warte auf Reader…", false, None::<&str>)?;
    // Menu-bar app layout: status, actions, settings/about, quit ("<App> beenden", as macOS names it).
    let about = AboutMetadata {
        name: Some("SpoolTap".into()),
        version: Some(app.package_info().version.to_string()),
        comments: Some("NFC-Tags für Spoolman lesen, verknüpfen und beschreiben.".into()),
        ..Default::default()
    };
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open", "Spoolman öffnen", true, Some("CmdOrCtrl+O"))?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "settings", "Einstellungen…", true, Some("CmdOrCtrl+,"))?,
            &PredefinedMenuItem::about(app, Some("Über SpoolTap"), Some(about))?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "SpoolTap beenden", true, Some("CmdOrCtrl+Q"))?,
        ],
    )?;
    *state(app).status.lock().unwrap() = Some(status);
    *state(app).tray_menu.lock().unwrap() = Some(menu.clone());
    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .tooltip("SpoolTap")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(move |app, e| match e.id.as_ref() {
            "open" => open_spoolman_path(app, "/"),
            "update" => {
                if let Some(v) = state(app).update_shown.lock().unwrap().clone() {
                    let _ = app.opener().open_url(release_url(&v), None::<&str>);
                }
            }
            "settings" => open_settings(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        // a second launch (e.g. two login items) just exits
        .plugin(tauri_plugin_single_instance::init(|_, _, _| {}))
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, None))
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let handle = app.handle().clone();
            let first_run = load_settings(&handle).is_none();
            let mut settings = load_settings(&handle).or_else(legacy_settings).unwrap_or_else(|| Settings {
                base_url: "http://localhost:7912".into(),
                ..Default::default()
            });
            if !settings.login_asked {
                settings.login_asked = true; // first launch: enable autostart once, user can untick
                let _ = handle.autolaunch().enable();
            }
            store_settings(&handle, &settings);
            let wanted = Arc::new(Mutex::new(settings.reader.clone()));
            let busy = Arc::new(AtomicBool::new(false));
            app.manage(AppState {
                settings: Mutex::new(settings.clone()),
                wanted_reader: wanted.clone(),
                card_busy: busy.clone(),
                current: Mutex::new(None),
                panel: Mutex::new(Value::Null),
                panel_busy: AtomicBool::new(false),
                copy: Mutex::new(None),
                status: Mutex::new(None),
                tray_menu: Mutex::new(None),
                update_shown: Mutex::new(None),
                // Explicit User-Agent: a "(unknown version) … Darwin/" agent on a JSON POST matches the
                // Suricata rule "ET MALWARE BlueNoroff APT Related Activity M1 (POST)" (sid 2049882)
                // and gets the machine blocked by IPS-enabled routers (e.g. UniFi).
                http: reqwest::Client::builder()
                    .user_agent("SpoolTap/1.0")
                    .timeout(std::time::Duration::from_secs(8))
                    .build()?,
            });
            build_tray(&handle)?;
            spawn_update_check(handle.clone());
            if first_run && settings.base_url == "http://localhost:7912" {
                open_settings(&handle);
            }
            // Debug builds only: SPOOLTAP_DEMO=1 opens the info panel with sample data (layout checks without a tag).
            #[cfg(debug_assertions)]
            if std::env::var("SPOOLTAP_DEMO").as_deref() == Ok("settings") {
                open_settings(&handle);
            } else if std::env::var_os("SPOOLTAP_DEMO").is_some() {
                let spool = json!({ "id": 3, "remaining_weight": 1000.0, "filament": { "name": "NX2-MATT - White",
                    "material": "PLA", "color_hex": "F4F4F4", "weight": 1000.0, "vendor": { "name": "Extrudr" } },
                    "tags": [{ "uid": "1A2B3C4D" }] });
                open_panel(&handle, json!({ "kind": "info", "uid": "1A2B3C4D", "spool": spool }));
            }
            let h = handle.clone();
            reader::spawn(wanted, busy, move |ev| match ev {
                reader::Event::Present { reader, uid } => {
                    tauri::async_runtime::spawn(on_present(h.clone(), reader, uid));
                }
                reader::Event::Removed => {
                    let h2 = h.clone();
                    let _ = h.run_on_main_thread(move || on_removed(&h2));
                }
                reader::Event::Status(s) => set_status(&h, &s),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            api,
            test_connection,
            open_release_notes,
            get_panel,
            set_panel_busy,
            close_panel,
            fit_panel,
            open_spoolman,
            show_info,
            arm_copy,
            disarm_copy,
            set_status_text,
            get_settings,
            save_settings,
            cfs_materials,
            cfs_suggest,
            cfs_read,
            cfs_wipe,
            cfs_write
        ])
        .build(tauri::generate_context!())
        .expect("SpoolTap konnte nicht starten")
        .run(|_, event| {
            // tray app: closing the last window must not quit
            if let tauri::RunEvent::ExitRequested { api, code: None, .. } = event {
                api.prevent_exit();
            }
        });
}
