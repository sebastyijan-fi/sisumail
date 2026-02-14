#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
  net::{SocketAddr, TcpStream},
  process::{Child, Command, Stdio},
  thread,
  time::{Duration, Instant},
};

fn is_listening(addr: &str, timeout: Duration) -> bool {
  let Ok(sa) = addr.parse::<SocketAddr>() else { return false };
  TcpStream::connect_timeout(&sa, timeout).is_ok()
}

fn start_core() -> Result<Child, String> {
  // v1: run `sisumail` from PATH. Next: bundle a sidecar so this is fully self-contained.
  Command::new("sisumail")
    .arg("-api-listen")
    .arg("127.0.0.1:3490")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|e| format!("failed to start sisumail core (is it installed on PATH?): {e}"))
}

fn wait_for_core(addr: &str, deadline: Duration) -> bool {
  let start = Instant::now();
  while start.elapsed() < deadline {
    if is_listening(addr, Duration::from_millis(120)) {
      return true;
    }
    thread::sleep(Duration::from_millis(120));
  }
  false
}

fn main() {
  tauri::Builder::default()
    .setup(|app| {
      let url = "http://127.0.0.1:3490/app";
      let listen = "127.0.0.1:3490";

      // Start core if it isn't already up.
      let mut child: Option<Child> = None;
      if !is_listening(listen, Duration::from_millis(150)) {
        match start_core() {
          Ok(c) => child = Some(c),
          Err(e) => {
            // Show a simple error page in the main window.
            let w = tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::Html(format!(
              "<!doctype html><meta charset=utf-8><title>Sisumail</title>\
               <style>body{{font-family:system-ui,Segoe UI,sans-serif;padding:24px;max-width:760px;margin:0 auto;}}\
               code{{background:#f3f3f3;padding:2px 6px;border-radius:6px;}}</style>\
               <h1>Sisumail</h1><p>Could not start the Sisumail core.</p>\
               <pre>{}</pre>\
               <p>Fix: install <code>sisumail</code> (or we bundle it as a sidecar next).</p>",
              html_escape(&e)
            ))).build()?;
            w.show()?;
            return Ok(());
          }
        }
      }

      // Wait briefly for core to come up (or already be up).
      if !wait_for_core(listen, Duration::from_secs(3)) {
        let w = tauri::WebviewWindowBuilder::new(
          app,
          "main",
          tauri::WebviewUrl::Html(
            "<!doctype html><meta charset=utf-8><title>Sisumail</title>\
             <style>body{font-family:system-ui,Segoe UI,sans-serif;padding:24px;max-width:760px;margin:0 auto;}</style>\
             <h1>Sisumail</h1><p>Core is starting… but did not become ready in time.</p>\
             <p>Try again in a moment.</p>"
              .to_string(),
          ),
        )
        .build()?;
        w.show()?;
        // Ensure we don't leave a zombie if we started it and failed.
        if let Some(mut c) = child {
          let _ = c.kill();
        }
        return Ok(());
      }

      let w = tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::External(url.parse().unwrap()))
        .title("Sisumail")
        .build()?;
      w.show()?;

      // Keep the child alive as long as the app runs.
      // Note: this is intentionally leaked; we'll add graceful shutdown later.
      if let Some(c) = child {
        std::mem::forget(c);
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

fn html_escape(s: &str) -> String {
  s.replace('&', "&amp;")
    .replace('<', "&lt;")
    .replace('>', "&gt;")
    .replace('"', "&quot;")
    .replace('\'', "&#39;")
}
