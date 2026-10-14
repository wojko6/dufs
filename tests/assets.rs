mod fixtures;
mod utils;

use assert_fs::fixture::TempDir;
#[cfg(unix)]
use fixtures::{port, wait_for_port};
use fixtures::{server, tmpdir, Error, TestServer, DIR_ASSETS};
use rstest::rstest;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

#[rstest]
fn assets(server: TestServer) -> Result<(), Error> {
    let ver = env!("CARGO_PKG_VERSION");
    let resp = reqwest::blocking::get(server.url())?;
    let index_js = format!("/__dufs_v{ver}__/index.js");
    let index_css = format!("/__dufs_v{ver}__/index.css");
    let favicon_ico = format!("/__dufs_v{ver}__/favicon.ico");
    let text = resp.text()?;
    println!("{text}");
    assert!(text.contains(&format!(r#"href="{index_css}?v="#)));
    assert!(text.contains(&format!(r#"href="{favicon_ico}?v="#)));
    assert!(text.contains(&format!(r#"src="{index_js}?v="#)));
    Ok(())
}

#[rstest]
fn asset_js(server: TestServer) -> Result<(), Error> {
    let url = format!(
        "{}__dufs_v{}__/index.js",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/javascript; charset=UTF-8"
    );
    Ok(())
}

#[rstest]
fn asset_css(server: TestServer) -> Result<(), Error> {
    let url = format!(
        "{}__dufs_v{}__/index.css",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/css; charset=UTF-8"
    );
    Ok(())
}

#[rstest]
fn asset_ico(server: TestServer) -> Result<(), Error> {
    let url = format!(
        "{}__dufs_v{}__/favicon.ico",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/x-icon");
    Ok(())
}

#[rstest]
fn assets_with_prefix(#[with(&["--path-prefix", "xyz"])] server: TestServer) -> Result<(), Error> {
    let ver = env!("CARGO_PKG_VERSION");
    let resp = reqwest::blocking::get(format!("{}xyz/", server.url()))?;
    let index_js = format!("/xyz/__dufs_v{ver}__/index.js");
    let index_css = format!("/xyz/__dufs_v{ver}__/index.css");
    let favicon_ico = format!("/xyz/__dufs_v{ver}__/favicon.ico");
    let text = resp.text()?;
    assert!(text.contains(&format!(r#"href="{index_css}?v="#)));
    assert!(text.contains(&format!(r#"href="{favicon_ico}?v="#)));
    assert!(text.contains(&format!(r#"src="{index_js}?v="#)));
    Ok(())
}

#[rstest]
fn asset_js_with_prefix(
    #[with(&["--path-prefix", "xyz"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!(
        "{}xyz/__dufs_v{}__/index.js",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/javascript; charset=UTF-8"
    );
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn assets_override(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    // Trusted UI assets must not reside under the served data root.
    // Put an independent copy of the fixture's custom index in a sibling
    // TempDir: this tests actual --assets compatibility without restoring
    // the attacker-writable same-origin boundary.
    let separate_assets = TempDir::new()?;
    std::fs::copy(
        tmpdir.join(format!("{DIR_ASSETS}index.html")),
        separate_assets.join("index.html"),
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("--assets")
        .arg(separate_assets.path())
        .stdout(Stdio::piped())
        .spawn()?;

    wait_for_port(port);

    let url = format!("http://localhost:{port}");
    let resp = reqwest::blocking::get(&url)?;
    assert!(resp.text()?.starts_with(&format!(
        "/__dufs_v{}__/index.js;<template id=\"index-data\">",
        env!("CARGO_PKG_VERSION")
    )));
    let resp = reqwest::blocking::get(&url)?;
    assert_resp_paths!(resp);

    child.kill()?;
    Ok(())
}

// On platforms without an fd-relative trusted-asset implementation, reject
// external --assets at startup. Do not silently trust data-root HTML.
#[cfg(windows)]
#[rstest]
fn custom_assets_fail_closed_without_fd_isolation(tmpdir: TempDir) -> Result<(), Error> {
    let external_assets = TempDir::new()?;
    std::fs::copy(
        tmpdir.join(format!("{DIR_ASSETS}index.html")),
        external_assets.join("index.html"),
    )?;
    let output = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("--assets")
        .arg(external_assets.path())
        .output()?;
    assert!(
        !output.status.success(),
        "custom assets must be refused without an fd-relative implementation"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("not supported") || stderr.contains("unsupported"),
        "unexpected startup error: {stderr}"
    );
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn assets_nested_in_data_root_use_builtin_ui(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS))
        .stdout(Stdio::piped())
        .spawn()?;

    wait_for_port(port);
    let url = format!("http://localhost:{port}");
    let html = reqwest::blocking::get(&url)?.text()?;
    let ver = env!("CARGO_PKG_VERSION");
    assert!(!html.contains("__ASSETS_REV__"));
    assert!(!html.starts_with(&format!("/__dufs_v{ver}__/index.js;")));
    assert!(html.contains(&format!(r#"src="/__dufs_v{ver}__/index.js?v="#)));
    let js = reqwest::blocking::get(format!("{url}/__dufs_v{ver}__/index.js"))?;
    assert_eq!(js.status(), 200);
    assert_eq!(
        js.headers().get("content-type").unwrap(),
        "application/javascript; charset=UTF-8"
    );

    child.kill()?;
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn assets_override_not_found_page(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let not_found_html = "<html><body>custom 404 page</body></html>";
    std::fs::write(
        tmpdir.join(format!("{}404.html", DIR_ASSETS)),
        not_found_html,
    )?;

    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS))
        .stdout(Stdio::piped())
        .spawn()?;

    wait_for_port(port);

    let url = format!("http://localhost:{port}/missing-path");
    let resp = reqwest::blocking::get(&url)?;
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.text()?, not_found_html);

    let url = format!("http://localhost:{port}/missing-path?noscript");
    let resp = reqwest::blocking::get(&url)?;
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.text()?, "Not Found");

    child.kill()?;
    Ok(())
}
