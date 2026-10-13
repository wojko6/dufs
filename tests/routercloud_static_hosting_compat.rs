mod fixtures;

use fixtures::{server, Error, TestServer};
use rstest::rstest;

#[rstest]
#[case(server(&["--render-index"] as &[&str]), false)]
#[case(server(&["--render-try-index"] as &[&str]), false)]
#[case(server(&["--render-spa"] as &[&str]), true)]
fn explicit_site_hosting_preserves_inline(
    #[case] server: TestServer,
    #[case] spa: bool,
) -> Result<(), Error> {
    std::fs::write(
        server.path().join("app.js"),
        "console.log('synthetic fixture');",
    )?;

    let client = reqwest::blocking::Client::builder().no_proxy().build()?;

    let mut paths = vec!["", "index.html", "dir1/", "app.js"];

    if spa {
        paths.push("synthetic-client-route");
    }

    for path in paths {
        let response = client.get(format!("{}{}", server.url(), path)).send()?;

        assert_eq!(response.status(), 200, "{path}");

        let disposition = response
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        assert!(
            disposition.starts_with("inline;"),
            "{path}: expected inline, received {disposition}"
        );

        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "{path}: nosniff missing"
        );
    }

    Ok(())
}
