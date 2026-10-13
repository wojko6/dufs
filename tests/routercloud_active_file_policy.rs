mod fixtures;

use fixtures::{server, Error, TestServer};
use rstest::rstest;

#[rstest]
fn active_user_files_require_download_protection(
    #[with(&[
        "--auth",
        "auditor:synthetic-only@/:ro",
        "--auth-method",
        "basic",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::builder().no_proxy().build()?;

    let cases = [
        ("active.html", "<h1>Safe fixture</h1>", "text/html"),
        (
            "active.svg",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
            "image/svg+xml",
        ),
        ("active.xml", "<test>safe</test>", "text/xml"),
    ];

    let mut failures = Vec::new();

    for (name, body, mime) in cases {
        std::fs::write(server.path().join(name), body)?;

        let response = client
            .get(format!("{}{}", server.url(), name))
            .basic_auth("auditor", Some("synthetic-only"))
            .send()?;

        assert_eq!(response.status(), 200, "{name}");

        let headers = response.headers();

        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        assert!(
            content_type.starts_with(mime),
            "{name}: unexpected Content-Type: {content_type}"
        );

        let disposition = headers
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !disposition.starts_with("attachment;") {
            failures.push(format!("{name}: unsafe Content-Disposition: {disposition}"));
        }

        let nosniff = headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok());

        if nosniff != Some("nosniff") {
            failures.push(format!("{name}: X-Content-Type-Options missing"));
        }
    }

    assert!(
        failures.is_empty(),
        "Active-file security policy violations:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[rstest]
fn text_preview_remains_inline(
    #[with(&[
        "--auth",
        "auditor:synthetic-only@/:ro",
        "--auth-method",
        "basic",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::builder().no_proxy().build()?;

    let response = client
        .get(format!("{}test.txt", server.url()))
        .basic_auth("auditor", Some("synthetic-only"))
        .send()?;

    assert_eq!(response.status(), 200);

    let disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        disposition.starts_with("inline;"),
        "Text preview regression: {disposition}"
    );

    Ok(())
}
