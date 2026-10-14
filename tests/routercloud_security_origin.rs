mod fixtures;

use assert_fs::fixture::TempDir;
use fixtures::{port, server, tmpdir, wait_for_port, Error, TestServer};
use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use rstest::rstest;
use std::fs;
use std::process::{Command, Stdio};

fn authenticated_file(server: &TestServer, name: &str, body: &str) -> Result<Response, Error> {
    fs::write(server.path().join(name), body)?;

    let client = Client::builder().no_proxy().build()?;
    let url = server.url().join(name)?;

    let guest = client.get(url.clone()).send()?;
    assert_eq!(guest.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .get(url)
        .basic_auth("issue235", Some("local-fixture"))
        .send()?;

    assert_eq!(response.status(), StatusCode::OK);

    Ok(response)
}

#[rstest]
#[case("check.html", "<!doctype html><title>Lab fixture</title>")]
#[case("check.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>")]
fn active_file_must_be_downloaded(
    #[with(&[
        "--bind", "127.0.0.1",
        "--auth", "issue235:local-fixture@/:ro",
        "--auth-method", "basic"
    ])]
    server: TestServer,
    #[case] name: &str,
    #[case] body: &str,
) -> Result<(), Error> {
    let response = authenticated_file(&server, name, body)?;

    let disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("ABSENT");

    assert!(
        disposition.starts_with("attachment;"),
        "EXPECTED_ATTACHMENT_FOR_USER_ACTIVE_FILE: {disposition}"
    );

    Ok(())
}

#[rstest]
#[case("check.html", "<!doctype html><title>Lab fixture</title>")]
#[case("check.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>")]
fn user_file_must_have_nosniff(
    #[with(&[
        "--bind", "127.0.0.1",
        "--auth", "issue235:local-fixture@/:ro",
        "--auth-method", "basic"
    ])]
    server: TestServer,
    #[case] name: &str,
    #[case] body: &str,
) -> Result<(), Error> {
    let response = authenticated_file(&server, name, body)?;

    let nosniff = response
        .headers()
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("ABSENT");

    assert_eq!(nosniff, "nosniff", "EXPECTED_NOSNIFF_FOR_USER_FILE");

    Ok(())
}

#[rstest]
fn issue235_extended_active_matrix(
    #[with(&[
        "--bind", "127.0.0.1",
        "--auth", "issue235:local-fixture@/:ro",
        "--auth-method", "basic"
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let client = Client::builder().no_proxy().build()?;

    let active = [
        "check.html",
        "check.svg",
        "check.xml",
        "check.xhtml",
        "check.xsl",
        "check.mht",
        "check.HTM",
        "check.svgz",
        "check.js",
    ];

    for name in active {
        fs::write(server.path().join(name), "Issue 235 synthetic fixture")?;

        let url = server.url().join(name)?;

        let guest = client.get(url.clone()).send()?;
        assert_eq!(
            guest.status(),
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED_FILE_ACCESS: {name}"
        );

        for head in [false, true] {
            let request = if head {
                client.head(url.clone())
            } else {
                client.get(url.clone())
            };

            let response = request
                .basic_auth("issue235", Some("local-fixture"))
                .send()?;

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "ACTIVE_FILE_STATUS: {name} HEAD={head}"
            );

            let headers = response.headers();

            let disposition = headers
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("ABSENT");

            assert!(
                disposition.starts_with("attachment;"),
                "ACTIVE_FILE_NOT_ATTACHMENT: {name} HEAD={head}: {disposition}"
            );

            assert_eq!(
                headers
                    .get("x-content-type-options")
                    .and_then(|v| v.to_str().ok()),
                Some("nosniff"),
                "ACTIVE_FILE_NOSNIFF: {name}"
            );

            assert_eq!(
                headers
                    .get("content-security-policy")
                    .and_then(|v| v.to_str().ok()),
                Some("sandbox"),
                "ACTIVE_FILE_CSP: {name}"
            );
        }
    }

    Ok(())
}

#[rstest]
fn issue235_ranges_and_inert_preview(
    #[with(&[
        "--bind", "127.0.0.1",
        "--auth", "issue235:local-fixture@/:ro",
        "--auth-method", "basic"
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let client = Client::builder().no_proxy().build()?;

    fs::write(
        server.path().join("check.html"),
        "<!doctype html><title>Synthetic range fixture</title>",
    )?;

    let url = server.url().join("check.html")?;

    for range in ["bytes=0-4", "bytes=0-4,10-14"] {
        let response = client
            .get(url.clone())
            .header("Range", range)
            .basic_auth("issue235", Some("local-fixture"))
            .send()?;

        assert_eq!(
            response.status(),
            StatusCode::PARTIAL_CONTENT,
            "RANGE_STATUS: {range}"
        );

        let headers = response.headers();

        assert!(
            headers
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .starts_with("attachment;"),
            "RANGE_ATTACHMENT: {range}"
        );

        assert_eq!(
            headers
                .get("content-security-policy")
                .and_then(|v| v.to_str().ok()),
            Some("sandbox"),
            "RANGE_CSP: {range}"
        );
    }

    let passive = [
        ("photo.png", b"\x89PNG\r\n\x1a\n".as_slice()),
        ("document.pdf", b"%PDF-1.4\n%%EOF\n".as_slice()),
    ];

    for (name, bytes) in passive {
        fs::write(server.path().join(name), bytes)?;

        let url = server.url().join(name)?;

        for head in [false, true] {
            let request = if head {
                client.head(url.clone())
            } else {
                client.get(url.clone())
            };

            let response = request
                .basic_auth("issue235", Some("local-fixture"))
                .send()?;

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "PASSIVE_FILE_STATUS: {name}"
            );

            let headers = response.headers();

            assert!(
                headers
                    .get("content-disposition")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .starts_with("inline;"),
                "PASSIVE_FILE_INLINE: {name}"
            );

            assert_eq!(
                headers
                    .get("x-content-type-options")
                    .and_then(|v| v.to_str().ok()),
                Some("nosniff"),
                "PASSIVE_FILE_NOSNIFF: {name}"
            );
        }
    }

    Ok(())
}

#[rstest]
fn issue235_custom_error_page_untrusted(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let page = tmpdir.path().join("user404.html");
    fs::write(&page, "<!doctype html><title>Synthetic 404</title>")?;

    let config = tmpdir.path().join("config.yaml");
    let quoted_path = serde_json::to_string(&page.to_string_lossy().to_string())?;

    fs::write(&config, format!("error-page: {quoted_path}\n"))?;

    let child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .args(["--bind", "127.0.0.1"])
        .arg("--port")
        .arg(port.to_string())
        .arg("--config")
        .arg(&config)
        .args([
            "--auth",
            "issue235:local-fixture@/:ro",
            "--auth-method",
            "basic",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let server = TestServer::new(port, tmpdir, child, false);
    wait_for_port(port);

    let response = Client::builder()
        .no_proxy()
        .build()?
        .get(server.url().join("missing-page")?)
        .basic_auth("issue235", Some("local-fixture"))
        .send()?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let headers = response.headers();

    let disposition = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("ABSENT");

    assert!(
        disposition.starts_with("attachment;"),
        "ERROR_PAGE_TRUST_BYPASS: {disposition}"
    );

    assert_eq!(
        headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok()),
        Some("sandbox")
    );

    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );

    Ok(())
}

#[rstest]
#[case(false, "inline;", false)]
#[case(true, "attachment;", true)]
fn issue235_custom_error_page_trust_boundary(
    tmpdir: TempDir,
    port: u16,
    #[case] assets_inside_data: bool,
    #[case] expected_disposition: &str,
    #[case] expected_sandbox: bool,
) -> Result<(), Error> {
    let external_assets = TempDir::new()?;

    let assets_path = if assets_inside_data {
        tmpdir.path().join("embedded-assets")
    } else {
        external_assets.path().to_path_buf()
    };

    fs::create_dir_all(&assets_path)?;

    fs::write(
        assets_path.join("index.html"),
        "<!doctype html><title>Trusted fixture</title>",
    )?;

    fs::write(
        assets_path.join("404.html"),
        "<!doctype html><title>404 fixture</title>",
    )?;

    let child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .args(["--bind", "127.0.0.1"])
        .arg("--port")
        .arg(port.to_string())
        .arg("--assets")
        .arg(&assets_path)
        .args([
            "--auth",
            "issue235:local-fixture@/:ro",
            "--auth-method",
            "basic",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let server = TestServer::new(port, tmpdir, child, false);
    wait_for_port(port);

    let response = Client::builder()
        .no_proxy()
        .build()?
        .get(server.url().join("missing-page")?)
        .basic_auth("issue235", Some("local-fixture"))
        .send()?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("ABSENT");

    assert!(
        disposition.starts_with(expected_disposition),
        "404_TRUST_BOUNDARY: {disposition}"
    );

    let csp = response
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok());

    if expected_sandbox {
        assert_eq!(csp, Some("sandbox"));
    } else {
        assert_eq!(csp, None);
    }

    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );

    Ok(())
}

#[cfg(unix)]
#[rstest]
#[case("asset", "linked.html")]
#[case("login", "login.html")]
fn issue235_symlinked_trusted_asset_must_be_rejected(
    tmpdir: TempDir,
    port: u16,
    #[case] route_kind: &str,
    #[case] asset_name: &str,
) -> Result<(), Error> {
    use std::os::unix::fs::symlink;

    let assets = TempDir::new()?;

    let payload = tmpdir.path().join("outside.html");

    fs::write(&payload, "<!doctype html><title>Untrusted fixture</title>")?;

    fs::write(
        assets.path().join("index.html"),
        "<!doctype html><title>Trusted fixture</title>",
    )?;

    symlink(&payload, assets.path().join(asset_name))?;

    let child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .args(["--bind", "127.0.0.1"])
        .arg("--port")
        .arg(port.to_string())
        .arg("--assets")
        .arg(assets.path())
        .args([
            "--auth",
            "issue235:local-fixture@/:ro",
            "--auth-method",
            "basic",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let server = TestServer::new(port, tmpdir, child, false);
    wait_for_port(port);

    let path = if route_kind == "login" {
        "/__routercloud/login".to_string()
    } else {
        format!("/__dufs_v{}__/linked.html", env!("CARGO_PKG_VERSION"))
    };

    let response = Client::builder()
        .no_proxy()
        .build()?
        .get(server.url().join(&path)?)
        .basic_auth("issue235", Some("local-fixture"))
        .send()?;

    assert!(
        matches!(response.status().as_u16(), 403 | 404),
        "TRUSTED_ASSET_SYMLINK_ESCAPE: path={path}, \
         status={}, disposition={:?}, csp={:?}",
        response.status(),
        response.headers().get("content-disposition"),
        response.headers().get("content-security-policy")
    );

    Ok(())
}

#[cfg(target_os = "linux")]
#[rstest]
fn issue235_startup_index_symlink_is_rejected(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};

    let data = tmpdir.path().join("data");
    fs::create_dir(&data)?;

    let assets = TempDir::new()?;
    let payload = data.join("untrusted.html");

    fs::write(&payload, "<!doctype html><title>Untrusted index</title>")?;

    symlink(&payload, assets.path().join("index.html"))?;

    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(&data)
        .args(["--bind", "127.0.0.1"])
        .arg("--port")
        .arg(port.to_string())
        .arg("--assets")
        .arg(assets.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let started = Instant::now();

    let exit_status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }

        if started.elapsed() >= Duration::from_secs(3) {
            break None;
        }

        std::thread::sleep(Duration::from_millis(50));
    };

    if exit_status.is_none() {
        child.kill()?;
        child.wait()?;
    }

    assert!(
        matches!(exit_status, Some(status) if !status.success()),
        "STARTUP_INDEX_SYMLINK_ACCEPTED"
    );

    Ok(())
}

// ISSUE235_TRUSTED_ASSETS_FD_V3_HTTP_REGRESSION
#[cfg(target_os = "linux")]
#[rstest]
fn issue235_trusted_http_assets_survive_root_path_replacement(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new()?;
    let assets = workspace.path().join("assets");
    let moved = workspace.path().join("original-assets");
    fs::create_dir(&assets)?;
    fs::write(
        assets.join("index.html"),
        "<!doctype html><title>Trusted</title>",
    )?;
    fs::write(assets.join("index.css"), "/* pinned trusted asset */")?;
    fs::write(assets.join("login.css"), "/* pinned trusted login */")?;
    fs::write(
        assets.join("404.html"),
        "<!doctype html><title>Pinned 404</title>",
    )?;

    // Synthetic user files are *not* supposed to become trusted assets.
    fs::write(tmpdir.path().join("index.css"), "/* untrusted css */")?;
    fs::write(tmpdir.path().join("login.css"), "/* untrusted login */")?;
    fs::write(
        tmpdir.path().join("404.html"),
        "<!doctype html><title>Untrusted 404</title>",
    )?;

    let child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .args(["--bind", "127.0.0.1"])
        .arg("--port")
        .arg(port.to_string())
        .arg("--assets")
        .arg(&assets)
        .args([
            "--auth",
            "issue235:local-fixture@/:ro",
            "--auth-method",
            "basic",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let server = TestServer::new(port, tmpdir, child, false);
    wait_for_port(port);

    // After startup the assets path resolves into the user-controlled data
    // directory. An unpinned path re-open would now serve untrusted bytes.
    fs::rename(&assets, &moved)?;
    symlink(server.path(), &assets)?;

    let client = Client::builder().no_proxy().build()?;
    for (path, status, expected) in [
        (
            format!("/__dufs_v{}__/index.css", env!("CARGO_PKG_VERSION")),
            StatusCode::OK,
            "/* pinned trusted asset */",
        ),
        (
            "/__routercloud/login.css".to_string(),
            StatusCode::OK,
            "/* pinned trusted login */",
        ),
        (
            "/nonexistent-issue235-file".to_string(),
            StatusCode::NOT_FOUND,
            "<!doctype html><title>Pinned 404</title>",
        ),
    ] {
        let response = client
            .get(server.url().join(&path)?)
            .basic_auth("issue235", Some("local-fixture"))
            .send()?;
        assert_eq!(response.status(), status, "unexpected status: {path}");
        assert_eq!(response.text()?, expected, "trusted bytes changed: {path}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[rstest]
fn issue235_trusted_http_nested_directory_symlink_is_rejected(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    use std::os::unix::fs::symlink;

    let assets = TempDir::new()?;
    fs::write(
        assets.path().join("index.html"),
        "<!doctype html><title>Trusted</title>",
    )?;
    let outside = tmpdir.path().join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("payload.js"), "/* untrusted nested asset */")?;
    symlink(&outside, assets.path().join("linked"))?;

    let child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .args(["--bind", "127.0.0.1"])
        .arg("--port")
        .arg(port.to_string())
        .arg("--assets")
        .arg(assets.path())
        .args([
            "--auth",
            "issue235:local-fixture@/:ro",
            "--auth-method",
            "basic",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let server = TestServer::new(port, tmpdir, child, false);
    wait_for_port(port);

    let route = format!("/__dufs_v{}__/linked/payload.js", env!("CARGO_PKG_VERSION"));
    let response = Client::builder()
        .no_proxy()
        .build()?
        .get(server.url().join(&route)?)
        .basic_auth("issue235", Some("local-fixture"))
        .send()?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}
