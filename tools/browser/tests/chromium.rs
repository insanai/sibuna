//! Drives a real Chromium against a tiny std-only HTTP server.
//!
//! Ignored by default because it needs `chromium` on PATH (or `$SIBUNA_CHROMIUM`). Run it
//! with `cargo test -p sibuna-browser -- --ignored`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use sibuna_browser::{Browser, Error, Options, RecordingOptions};

const PAGE: &str = r#"<!DOCTYPE html>
<html><head><title>Fixture</title>
<style>
@keyframes spin { to { transform: rotate(360deg); } }
#spinner { width: 40px; height: 40px; background: #36c; animation: spin 1s linear infinite; }
</style></head>
<body style="font: 24px sans-serif; background: #eef">
<h1 id="title">Browser fixture</h1>
<div id="spinner"></div>
<button id="button" onclick="document.getElementById('out').textContent = 'clicked'">Press</button>
<input id="name" oninput="document.getElementById('echo').textContent = this.value">
<p id="out">waiting</p><p id="echo"></p>
<script>
console.log('hello', 42);
console.error('boom');
fetch('http://127.0.0.1:1/unreachable').catch(() => {});
setTimeout(() => { throw new Error('late failure'); }, 0);
</script>
</body></html>"#;

const STATUS_PAGE: &str = r#"<!DOCTYPE html><html><body>
<script>window.__report && window.__report('from ' + location.pathname);</script>
</body></html>"#;

const WORKER_PAGE: &str = r#"<!DOCTYPE html><html><body><script>
const worker = new Worker('/worker.js');
worker.onmessage = (event) => { document.body.dataset.worker = event.data; };
document.body.dataset.page = typeof WebAssembly;
</script></body></html>"#;

const WORKER_SCRIPT: &str = "console.log('worker sees ' + typeof WebAssembly); \
    postMessage(typeof WebAssembly); setTimeout(() => { throw new Error('worker failure'); }, 0);";

/// Serves `PAGE` at `/` (with a cookie), a worker page and its script, and `STATUS_PAGE`
/// elsewhere, until dropped.
struct Server {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("the bound address").port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                // Acquire pairs with the Release store in Drop.
                if flag.load(Ordering::Acquire) {
                    break;
                }
                if let Ok(stream) = stream {
                    respond(stream);
                }
            }
        });
        Server { port, stop, thread: Some(thread) }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head);
    let path = head.split(' ').nth(1).unwrap_or("/");
    let (status, body, cookie) = match path {
        "/" => ("200 OK", PAGE, "Set-Cookie: fixture=1; Path=/; HttpOnly\r\n"),
        "/worker.html" => ("200 OK", WORKER_PAGE, ""),
        "/worker.js" => ("200 OK", WORKER_SCRIPT, "Content-Type: text/javascript\r\n"),
        "/favicon.ico" => ("404 Not Found", "", ""),
        _ => ("200 OK", STATUS_PAGE, ""),
    };
    let content_type = if cookie.starts_with("Content-Type") {
        ""
    } else {
        "Content-Type: text/html; charset=utf-8\r\n"
    };
    let response = format!(
        "HTTP/1.1 {status}\r\n{content_type}{cookie}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn options() -> Options {
    let mut options = Options::default();
    if let Some(path) = std::env::var_os("SIBUNA_CHROMIUM").filter(|path| !path.is_empty()) {
        options.executable = path.into();
    }
    options
}

fn scratch(name: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("sibuna-browser-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

#[test]
#[ignore = "needs chromium"]
fn drives_a_page_and_takes_a_screenshot() {
    let server = Server::start();
    let directory = scratch("drive");
    let mut browser = Browser::launch(options()).unwrap();
    let profile = browser.profile_dir().to_owned();
    assert!(browser.version().unwrap().contains("Chrome/"));
    let mut page = browser.new_page().unwrap();
    page.set_viewport(800, 600, false).unwrap();
    page.start_recording(&directory.join("frames"), RecordingOptions::default()).unwrap();
    page.navigate(&server.url("/")).unwrap();
    let title = page.wait_for("document.title", Duration::from_secs(5)).unwrap();
    // The spinner paints continuously: a screenshot while recording must still complete.
    page.screenshot(&directory.join("animated.png")).unwrap();
    assert_eq!(title.as_string().as_deref(), Some("Fixture"));

    // A command longer than one 4 KiB frame, and a result much larger than one.
    let long = format!("/*{}*/ 6 * 7", "x".repeat(10_000));
    assert_eq!(page.evaluate(&long).unwrap().as_f64(), Some(42.0));
    let big = page.evaluate("'y'.repeat(300000)").unwrap().as_string().unwrap();
    assert_eq!(big.len(), 300_000);
    assert!(matches!(page.evaluate("null.x"), Err(Error::Evaluation(_))));
    assert_eq!(page.evaluate("Promise.resolve(5)").unwrap().as_f64(), Some(5.0));

    page.click("#button").unwrap();
    page.wait_for(
        "document.getElementById('out').textContent === 'clicked'",
        Duration::from_secs(5),
    )
    .unwrap();
    page.type_text("#name", "Ada").unwrap();
    let echo = page.evaluate("document.getElementById('echo').textContent").unwrap();
    assert_eq!(echo.as_string().as_deref(), Some("Ada"));
    assert!(matches!(page.click("#missing"), Err(Error::NotFound(_))));
    let timeout = page.wait_for("false", Duration::from_millis(200));
    assert!(matches!(timeout, Err(Error::Timeout { .. })));

    page.wait_for("true", Duration::from_secs(1)).unwrap();
    page.idle_for(Duration::from_millis(300)).unwrap();
    let console: Vec<(String, String)> = page
        .console_messages()
        .iter()
        .map(|message| (message.level.clone(), message.text.clone()))
        .collect();
    assert!(console.contains(&("log".into(), "hello 42".into())), "{console:?}");
    assert!(console.contains(&("error".into(), "boom".into())), "{console:?}");
    assert!(page.exceptions().iter().any(|exception| exception.text.contains("late failure")));
    assert!(
        page.network_failures().iter().any(|failure| failure.url.contains("127.0.0.1:1/")),
        "{:?}",
        page.network_failures()
    );
    assert_eq!(page.document_responses()[0].status, 200);
    let cookies = page.cookies().unwrap();
    assert!(cookies.iter().any(|cookie| cookie.name == "fixture" && cookie.http_only));

    let screenshot = directory.join("page.png");
    page.screenshot(&screenshot).unwrap();
    let png = std::fs::read(&screenshot).unwrap();
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n") && png.len() > 1000);
    let recording = page.stop_recording().unwrap().unwrap();
    assert!(recording.frame_count >= 1);
    assert!(recording.directory.join("frame-00001.png").exists());

    drop(page);
    drop(browser);
    assert!(!profile.exists(), "the profile is removed on drop");
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
#[ignore = "needs chromium"]
fn bindings_and_init_scripts_survive_navigation() {
    let server = Server::start();
    let mut browser = Browser::launch(options()).unwrap();
    let mut page = browser.new_page().unwrap();
    page.add_binding("__report").unwrap();
    page.add_init_script("window.__early = 'yes';").unwrap();
    for path in ["/one", "/two"] {
        page.navigate(&server.url(path)).unwrap();
        let early = page.evaluate("window.__early").unwrap();
        assert_eq!(early.as_string().as_deref(), Some("yes"));
    }
    page.idle_for(Duration::from_millis(100)).unwrap();
    let payloads: Vec<&str> =
        page.binding_calls().iter().map(|call| call.payload.as_str()).collect();
    assert_eq!(payloads, ["from /one", "from /two"]);
    let refused = page.navigate("http://127.0.0.1:1/");
    // Chromium shows its error page for a refused connection; Page.navigate reports it.
    assert!(matches!(refused, Err(Error::Navigation(_))), "{refused:?}");
}

#[test]
#[ignore = "needs chromium"]
fn observes_workers_and_removes_webassembly() {
    let server = Server::start();
    let mut browser = Browser::launch(options()).unwrap();
    for disabled in [false, true] {
        let mut page = browser.new_page().unwrap();
        if disabled {
            page.disable_webassembly().unwrap();
        }
        page.navigate(&server.url("/worker.html")).unwrap();
        let seen = page.wait_for("document.body.dataset.worker", Duration::from_secs(5)).unwrap();
        let expected = if disabled { "undefined" } else { "object" };
        assert_eq!(seen.as_string().as_deref(), Some(expected));
        let in_page = page.evaluate("document.body.dataset.page").unwrap();
        assert_eq!(in_page.as_string().as_deref(), Some(expected));
        page.wait_for(
            "new Promise((done) => setTimeout(() => done(true), 200))",
            Duration::from_secs(5),
        )
        .unwrap();
        // A worker that is not paused may log before we attach; with the script installed
        // it is paused, so its first message is always seen.
        if disabled {
            let logged = page.console_messages().iter().any(|m| m.text == "worker sees undefined");
            assert!(logged, "{:?}", page.console_messages());
        }
        assert!(
            page.exceptions().iter().any(|exception| exception.text.contains("worker failure")),
            "{:?}",
            page.exceptions()
        );
    }
}
