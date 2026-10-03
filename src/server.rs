#![allow(clippy::too_many_arguments)]

use crate::auth::{hash_password_sha512, www_authenticate, AccessPaths, AccessPerm};
use crate::http_utils::{body_full, IncomingStream, LengthLimitedStream};
use crate::noscript::{detect_noscript, generate_noscript_html};
use crate::utils::{
    decode_uri, encode_uri, get_file_mtime_and_mode, get_file_name, glob, parse_range,
    try_get_file_name,
};
use crate::Args;

use anyhow::{anyhow, Result};
use async_zip::{tokio::write::ZipFileWriter, Compression, ZipDateTime, ZipEntryBuilder};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use chrono::{LocalResult, TimeZone, Utc};
use futures_util::{pin_mut, TryStreamExt};
use headers::{
    AcceptRanges, AccessControlAllowCredentials, AccessControlAllowOrigin, CacheControl,
    ContentLength, ContentType, ETag, HeaderMap, HeaderMapExt, IfMatch, IfModifiedSince,
    IfNoneMatch, IfRange, IfUnmodifiedSince, LastModified, Range,
};
use http_body_util::{combinators::BoxBody, BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::{
    body::Incoming,
    header::{
        HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, RANGE,
    },
    Method, StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::process::Stdio;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::sync::atomic::{self, AtomicBool};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::{fs, io};

use tokio_util::compat::FuturesAsyncWriteCompatExt;
use tokio_util::io::{ReaderStream, StreamReader};
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};
use xml::escape::escape_str_pcdata;

pub type Request = hyper::Request<Incoming>;
pub type Response = hyper::Response<BoxBody<Bytes, anyhow::Error>>;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const INDEX_CSS: &str = include_str!("../assets/index.css");
const INDEX_JS: &str = include_str!("../assets/index.js");
const FAVICON_ICO: &[u8] = include_bytes!("../assets/favicon.ico");
const INDEX_NAME: &str = "index.html";
const BUF_SIZE: usize = 65536;
const EDITABLE_TEXT_MAX_SIZE: u64 = 4194304; // 4M
const RESUMABLE_UPLOAD_MIN_SIZE: u64 = 20971520; // 20M
const HEALTH_CHECK_PATH: &str = "__dufs__/health";

const ROUTERCLOUD_LOGIN_PATH: &str = "/__routercloud/login";
const ROUTERCLOUD_LOGIN_CSS_PATH: &str = "/__routercloud/login.css";
const ROUTERCLOUD_LOGIN_JS_PATH: &str = "/__routercloud/login.js";
const ROUTERCLOUD_LOGOUT_PATH: &str = "/__routercloud/logout";

// ROUTERCLOUD_FAVORITES_API_V1
const ROUTERCLOUD_FAVORITES_PATH: &str = "/__routercloud/favorites";
const ROUTERCLOUD_FAVORITES_BODY_MAX: usize = 8192;
const ROUTERCLOUD_FAVORITES_MAX: usize = 256;
const ROUTERCLOUD_FAVORITES_VERSION: u8 = 1;

const ROUTERCLOUD_SESSION_COOKIE: &str = "__Host-routercloud_session";
const ROUTERCLOUD_SESSION_MAX_AGE: u64 = 60 * 60 * 12;
const ROUTERCLOUD_LOGIN_BODY_MAX: usize = 8192;

// ROUTERCLOUD_PASSWORD_RECOVERY_V1
const ROUTERCLOUD_PASSWORD_RESET_REQUEST_PATH: &str = "/__routercloud/password-reset/request";

const ROUTERCLOUD_PASSWORD_RESET_CONFIRM_PATH: &str = "/__routercloud/password-reset/confirm";

const ROUTERCLOUD_PASSWORD_RESET_BODY_MAX: usize = 8192;
const ROUTERCLOUD_PASSWORD_RESET_VERSION: u8 = 1;
const ROUTERCLOUD_PASSWORD_RESET_TTL_MS: u64 = 15 * 60 * 1000;
const ROUTERCLOUD_PASSWORD_RESET_COOLDOWN_MS: u64 = 60 * 1000;

#[derive(Debug, Deserialize, Serialize)]
struct RouterCloudPasswordResetStore {
    version: u8,
    user: String,
    token_sha256: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

// ROUTERCLOUD_PASSWORD_OVERRIDE_STORE_V1
const ROUTERCLOUD_PASSWORD_OVERRIDE_VERSION: u8 = 1;

#[derive(Debug, Deserialize, Serialize)]
struct RouterCloudPasswordOverrideStore {
    version: u8,
    user: String,
    password_sha512_crypt: String,
    updated_at_ms: u64,
}

fn routercloud_password_override_store_path_for(serve_path: &Path, user: &str) -> Result<PathBuf> {
    let parent = serve_path
        .parent()
        .ok_or_else(|| anyhow!("RouterCloud serve path has no parent"))?;

    let mut hasher = Sha256::new();

    hasher.update(user.as_bytes());

    let user_id = hex::encode(hasher.finalize());

    Ok(parent
        .join(".routercloud-system")
        .join("password-overrides")
        .join(format!("{user_id}.json")))
}

fn load_routercloud_password_override_sync(
    serve_path: &Path,
    user: &str,
) -> Result<Option<RouterCloudPasswordOverrideStore>> {
    let path = routercloud_password_override_store_path_for(serve_path, user)?;

    let data = match std::fs::read(&path) {
        Ok(data) => data,

        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }

        Err(err) => return Err(err.into()),
    };

    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode();

        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "RouterCloud password override permissions are too broad"
            ));
        }
    }

    let store: RouterCloudPasswordOverrideStore = serde_json::from_slice(&data)?;

    if store.version != ROUTERCLOUD_PASSWORD_OVERRIDE_VERSION
        || store.user != user
        || !store.password_sha512_crypt.starts_with("$6$")
    {
        return Err(anyhow!("Invalid RouterCloud password override store"));
    }

    Ok(Some(store))
}

const ROUTERCLOUD_EDIT_BODY_MAX: usize = EDITABLE_TEXT_MAX_SIZE as usize;
const ROUTERCLOUD_ZIP_SELECTION_BODY_MAX: usize = 65536;

pub const MAX_SUBPATHS_COUNT: u64 = 1000;

fn normalize_routercloud_favorite_path(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return None;
    }

    let path = Path::new(value);

    if path.is_absolute() {
        return None;
    }

    let mut parts = Vec::new();

    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_string_lossy();

                if value.is_empty() {
                    return None;
                }

                parts.push(value.to_string());
            }
            _ => return None,
        }
    }

    if parts.is_empty() {
        return None;
    }

    Some(parts.join("/"))
}

fn valid_routercloud_zip_selection_path(value: &str) -> bool {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return false;
    }

    let path = Path::new(value);

    if path.is_absolute() {
        return false;
    }

    let mut count = 0usize;

    for component in path.components() {
        match component {
            Component::Normal(_) => count += 1,
            _ => return false,
        }
    }

    count > 0
}

fn compute_assets_revision(assets_path: Option<&Path>) -> String {
    let mut hasher = Sha256::new();

    if let Some(assets_path) = assets_path {
        for name in ["index.html", "index.css", "index.js", "favicon.ico"] {
            hasher.update(name.as_bytes());
            if let Ok(data) = std::fs::read(assets_path.join(name)) {
                hasher.update(&data);
            }
        }
    } else {
        hasher.update(INDEX_HTML.as_bytes());
        hasher.update(INDEX_CSS.as_bytes());
        hasher.update(INDEX_JS.as_bytes());
        hasher.update(FAVICON_ICO);
    }

    let digest = hasher.finalize();
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{:02x}", *byte))
        .collect()
}

#[derive(Debug, Serialize)]
pub struct StorageInfo {
    pub total: u64,
    pub used: u64,
    pub available: u64,
}

#[cfg(unix)]
fn get_storage_info(path: &Path) -> Option<StorageInfo> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();

    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }

    let stat = unsafe { stat.assume_init() };

    let block_size = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };

    let total = (stat.f_blocks as u64).saturating_mul(block_size);
    let free = (stat.f_bfree as u64).saturating_mul(block_size);
    let available = (stat.f_bavail as u64).saturating_mul(block_size);

    Some(StorageInfo {
        total,
        used: total.saturating_sub(free),
        available,
    })
}

#[cfg(not(unix))]
fn get_storage_info(_path: &Path) -> Option<StorageInfo> {
    None
}

#[cfg(target_os = "linux")]
async fn rename_noreplace(path: &Path, dest: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let dest = CString::new(dest.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;

    tokio::task::spawn_blocking(move || {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::AT_FDCWD,
                dest.as_ptr(),
                libc::RENAME_NOREPLACE as libc::c_uint,
            )
        };

        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
    .await
    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
}

#[cfg(not(target_os = "linux"))]
async fn rename_noreplace(path: &Path, dest: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(dest).await {
        Ok(_) => Err(std::io::ErrorKind::AlreadyExists.into()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => fs::rename(path, dest).await,
        Err(err) => Err(err),
    }
}

pub struct Server {
    args: Args,
    assets_prefix: String,
    assets_revision: String,
    html: Cow<'static, str>,
    single_file_req_paths: Vec<String>,
    running: Arc<AtomicBool>,

    // Serializes reset-token creation and consumption.
    routercloud_password_reset_lock: Mutex<()>,
}

impl Server {
    pub fn init(args: Args, running: Arc<AtomicBool>) -> Result<Self> {
        /*
         * ROUTERCLOUD_PASSWORD_OVERRIDE_STORE_V1
         *
         * Password reset credentials survive process
         * restarts. Access permissions continue to come
         * exclusively from the normal DUFS auth config.
         */
        match (
            args.routercloud_password_recovery_user.clone(),
            args.routercloud_password_recovery_email.clone(),
        ) {
            (None, None) => {}

            (Some(user), Some(email)) => {
                if user.trim().is_empty() || email.trim().is_empty() {
                    return Err(anyhow!(
                        "Invalid RouterCloud password recovery configuration"
                    ));
                }

                if !args.auth.has_user(&user) {
                    return Err(anyhow!("RouterCloud password recovery user does not exist"));
                }

                if let Some(store) =
                    load_routercloud_password_override_sync(&args.serve_path, &user)?
                {
                    args.auth
                        .set_password_override(&user, store.password_sha512_crypt)?;

                    if !args.auth.has_password_override(&user) {
                        return Err(anyhow!("Failed to activate RouterCloud password override"));
                    }
                }
            }

            _ => {
                return Err(anyhow!(
                    "RouterCloud password recovery requires both user and email"
                ));
            }
        }

        let assets_prefix = format!("__dufs_v{}__/", env!("CARGO_PKG_VERSION"));
        let assets_revision = compute_assets_revision(args.assets.as_deref());
        let single_file_req_paths = if args.path_is_file {
            vec![
                args.uri_prefix.to_string(),
                args.uri_prefix[0..args.uri_prefix.len() - 1].to_string(),
                encode_uri(&format!(
                    "{}{}",
                    &args.uri_prefix,
                    get_file_name(&args.serve_path)
                )),
            ]
        } else {
            vec![]
        };
        let html = match args.assets.as_ref() {
            Some(path) => Cow::Owned(std::fs::read_to_string(path.join("index.html"))?),
            None => Cow::Borrowed(INDEX_HTML),
        };
        Ok(Self {
            args,
            running,
            single_file_req_paths,
            assets_prefix,
            assets_revision,
            html,
            routercloud_password_reset_lock: Mutex::new(()),
        })
    }

    pub async fn call(
        self: Arc<Self>,
        req: Request,
        addr: Option<SocketAddr>,
    ) -> Result<Response, hyper::Error> {
        let uri = req.uri().clone();
        let assets_prefix = &self.assets_prefix;
        let enable_cors = self.args.enable_cors;
        let mut http_log_data = self.args.http_logger.data(&req);
        if let Some(addr) = addr {
            http_log_data.insert("remote_addr".to_string(), addr.ip().to_string());
        }

        let mut res = match self.clone().handle(req).await {
            Ok(res) => {
                http_log_data.insert("status".to_string(), res.status().as_u16().to_string());
                if !uri.path().starts_with(assets_prefix) {
                    self.args.http_logger.log(&http_log_data, None);
                }
                res
            }
            Err(err) => {
                let mut res = Response::default();
                let status = StatusCode::INTERNAL_SERVER_ERROR;
                *res.status_mut() = status;
                http_log_data.insert("status".to_string(), status.as_u16().to_string());
                self.args
                    .http_logger
                    .log(&http_log_data, Some(err.to_string()));
                res
            }
        };

        if enable_cors {
            add_cors(&mut res);
        }
        Ok(res)
    }

    pub async fn handle(self: Arc<Self>, req: Request) -> Result<Response> {
        let mut res = Response::default();

        if req.uri().path() == ROUTERCLOUD_LOGIN_PATH {
            if req.method() == Method::GET {
                self.handle_routercloud_login_asset("login.html", req.headers(), &mut res)
                    .await?;
                return Ok(res);
            }

            if req.method() == Method::POST {
                self.handle_routercloud_login(req, &mut res).await?;
                return Ok(res);
            }

            *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            res.headers_mut()
                .insert("allow", HeaderValue::from_static("GET, POST"));
            return Ok(res);
        }

        // ROUTERCLOUD_PASSWORD_RECOVERY_V1
        if req.uri().path() == ROUTERCLOUD_PASSWORD_RESET_REQUEST_PATH {
            if req.method() != Method::POST {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;

                res.headers_mut()
                    .insert("allow", HeaderValue::from_static("POST"));

                return Ok(res);
            }

            self.handle_routercloud_password_reset_request(req, &mut res)
                .await?;

            return Ok(res);
        }

        // ROUTERCLOUD_PASSWORD_RESET_CONFIRM_V1
        if req.uri().path() == ROUTERCLOUD_PASSWORD_RESET_CONFIRM_PATH {
            if req.method() != Method::POST {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;

                res.headers_mut()
                    .insert("allow", HeaderValue::from_static("POST"));

                return Ok(res);
            }

            self.handle_routercloud_password_reset_confirm(req, &mut res)
                .await?;

            return Ok(res);
        }

        if req.uri().path() == ROUTERCLOUD_LOGIN_CSS_PATH {
            if req.method() != Method::GET {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                res.headers_mut()
                    .insert("allow", HeaderValue::from_static("GET"));
                return Ok(res);
            }

            self.handle_routercloud_login_asset("login.css", req.headers(), &mut res)
                .await?;
            return Ok(res);
        }

        if req.uri().path() == ROUTERCLOUD_LOGIN_JS_PATH {
            if req.method() != Method::GET {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                res.headers_mut()
                    .insert("allow", HeaderValue::from_static("GET"));
                return Ok(res);
            }

            self.handle_routercloud_login_asset("login.js", req.headers(), &mut res)
                .await?;
            return Ok(res);
        }

        if req.uri().path() == ROUTERCLOUD_LOGOUT_PATH {
            if req.method() != Method::POST {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                res.headers_mut()
                    .insert("allow", HeaderValue::from_static("POST"));
                return Ok(res);
            }

            self.handle_routercloud_logout(&mut res)?;
            return Ok(res);
        }

        if req.uri().path() == ROUTERCLOUD_FAVORITES_PATH {
            self.handle_routercloud_favorites(req, &mut res).await?;

            return Ok(res);
        }

        let req_path = req.uri().path();
        let headers = req.headers();
        let method = req.method().clone();

        let relative_path = match self.resolve_path(req_path) {
            Some(v) => v,
            None => {
                status_bad_request(&mut res, "Invalid Path");
                return Ok(res);
            }
        };

        if method == Method::GET
            && self
                .handle_internal(&relative_path, headers, &mut res)
                .await?
        {
            return Ok(res);
        }

        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase())
            .unwrap_or_default();

        let is_microsoft_webdav = user_agent.starts_with("microsoft-webdav-miniredir/");

        if is_microsoft_webdav {
            // microsoft webdav requires this.
            res.headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }

        let authorization = headers.get(AUTHORIZATION);

        let query = req.uri().query().unwrap_or_default();
        let mut query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let is_routercloud_zip_selection =
            method == Method::POST && has_query_flag(&query_params, "zip-selected");

        let explicit_token = method == Method::GET && query_params.contains_key("token");

        let guard = if is_routercloud_zip_selection {
            if authorization.is_some() {
                self.args
                    .auth
                    .guard_read_action(&relative_path, &method, authorization)
            } else if let Some(session_token) =
                get_cookie_value(headers, ROUTERCLOUD_SESSION_COOKIE)
            {
                match self.args.auth.verify_session_token(session_token) {
                    Ok((user, access_paths)) => {
                        (Some(user), access_paths.guard(&relative_path, &Method::GET))
                    }
                    Err(_) => self
                        .args
                        .auth
                        .guard_read_action(&relative_path, &method, None),
                }
            } else {
                self.args
                    .auth
                    .guard_read_action(&relative_path, &method, None)
            }
        } else if authorization.is_some() || explicit_token {
            self.args.auth.guard(
                &relative_path,
                &method,
                authorization,
                query_params.get("token"),
                is_microsoft_webdav,
            )
        } else if let Some(session_token) = get_cookie_value(headers, ROUTERCLOUD_SESSION_COOKIE) {
            match self.args.auth.verify_session_token(session_token) {
                Ok((user, access_paths)) => {
                    (Some(user), access_paths.guard(&relative_path, &method))
                }
                Err(_) => {
                    self.args
                        .auth
                        .guard(&relative_path, &method, None, None, is_microsoft_webdav)
                }
            }
        } else {
            self.args
                .auth
                .guard(&relative_path, &method, None, None, is_microsoft_webdav)
        };

        let (user, access_paths) = match guard {
            (None, None) => {
                if should_redirect_to_routercloud_login(
                    headers,
                    &method,
                    authorization,
                    is_microsoft_webdav,
                ) {
                    routercloud_login_redirect(&mut res);
                } else {
                    self.auth_reject(&mut res)?;
                }

                return Ok(res);
            }
            (Some(_), None) => {
                status_forbid(&mut res);
                return Ok(res);
            }
            (x, Some(y)) => (x, y),
        };

        if detect_noscript(&user_agent) {
            query_params.insert("noscript".to_string(), String::new());
        }

        if method.as_str() == "CHECKAUTH" {
            match user.clone() {
                Some(user) => {
                    *res.body_mut() = body_full(user);
                }
                None => {
                    if has_query_flag(&query_params, "login") || !access_paths.perm().readwrite() {
                        self.auth_reject(&mut res)?
                    } else {
                        *res.body_mut() = body_full("");
                    }
                }
            }
            return Ok(res);
        } else if method.as_str() == "LOGOUT" {
            self.auth_reject(&mut res)?;
            return Ok(res);
        }

        if has_query_flag(&query_params, "tokengen") {
            self.handle_tokengen(&relative_path, user, &mut res).await?;
            return Ok(res);
        }

        let head_only = method == Method::HEAD;

        if self.args.path_is_file {
            if self
                .single_file_req_paths
                .iter()
                .any(|v| v.as_str() == req_path)
            {
                self.handle_send_file(&self.args.serve_path, headers, head_only, &mut res)
                    .await?;
            } else {
                self.handle_not_found(&query_params, headers, head_only, &mut res)
                    .await?;
            }
            return Ok(res);
        }
        let path = match self.join_path(&relative_path) {
            Some(v) => v,
            None => {
                status_forbid(&mut res);
                return Ok(res);
            }
        };

        let path = path.as_path();

        let (is_miss, is_dir, is_file, size) = match fs::metadata(path).await.ok() {
            Some(meta) => (false, meta.is_dir(), meta.is_file(), meta.len()),
            None => (true, false, false, 0),
        };

        let allow_upload = self.args.allow_upload;
        let allow_move = self.args.allow_move;
        let allow_delete = self.args.allow_delete;
        let allow_remove = allow_delete || self.args.routercloud_allow_delete;
        let allow_routercloud_edit = self.args.routercloud_allow_edit;
        let allow_search = self.args.allow_search;
        let allow_archive = self.args.allow_archive;
        let render_index = self.args.render_index;
        let render_spa = self.args.render_spa;
        let render_try_index = self.args.render_try_index;

        if self.guard_root_contained(path).await {
            self.handle_not_found(&query_params, headers, head_only, &mut res)
                .await?;
            return Ok(res);
        }

        if is_routercloud_zip_selection {
            if !allow_archive || !is_dir {
                status_not_found(&mut res);
                return Ok(res);
            }

            self.handle_routercloud_zip_selection(path, req, access_paths, &mut res)
                .await?;

            return Ok(res);
        }

        match method {
            Method::GET | Method::HEAD => {
                if is_dir {
                    if render_try_index {
                        if allow_archive && has_query_flag(&query_params, "zip") {
                            if !allow_archive {
                                self.handle_not_found(&query_params, headers, head_only, &mut res)
                                    .await?;
                                return Ok(res);
                            }
                            self.handle_zip_dir(path, head_only, access_paths, &mut res)
                                .await?;
                        } else if allow_search && query_params.contains_key("q") {
                            self.handle_search_dir(
                                path,
                                &query_params,
                                head_only,
                                user,
                                access_paths,
                                &mut res,
                            )
                            .await?;
                        } else {
                            self.handle_render_index(
                                path,
                                &query_params,
                                headers,
                                head_only,
                                user,
                                access_paths,
                                &mut res,
                            )
                            .await?;
                        }
                    } else if render_index || render_spa {
                        self.handle_render_index(
                            path,
                            &query_params,
                            headers,
                            head_only,
                            user,
                            access_paths,
                            &mut res,
                        )
                        .await?;
                    } else if has_query_flag(&query_params, "zip") {
                        if !allow_archive {
                            status_not_found(&mut res);
                            return Ok(res);
                        }
                        self.handle_zip_dir(path, head_only, access_paths, &mut res)
                            .await?;
                    } else if allow_search && query_params.contains_key("q") {
                        self.handle_search_dir(
                            path,
                            &query_params,
                            head_only,
                            user,
                            access_paths,
                            &mut res,
                        )
                        .await?;
                    } else {
                        self.handle_ls_dir(
                            path,
                            true,
                            &query_params,
                            head_only,
                            user,
                            access_paths,
                            &mut res,
                        )
                        .await?;
                    }
                } else if is_file {
                    if has_query_flag(&query_params, "json") {
                        self.handle_file_json(path, head_only, &mut res).await?;
                    } else if has_query_flag(&query_params, "edit") {
                        self.handle_edit_file(path, DataKind::Edit, head_only, user, &mut res)
                            .await?;
                    } else if has_query_flag(&query_params, "view") {
                        self.handle_edit_file(path, DataKind::View, head_only, user, &mut res)
                            .await?;
                    } else if has_query_flag(&query_params, "hash") {
                        if self.args.allow_hash {
                            self.handle_hash_file(path, head_only, &mut res).await?;
                        } else {
                            status_forbid(&mut res);
                        }
                    } else {
                        self.handle_send_file(path, headers, head_only, &mut res)
                            .await?;
                    }
                } else if render_spa {
                    self.handle_render_spa(path, &query_params, headers, head_only, &mut res)
                        .await?;
                } else if allow_upload && req_path.ends_with('/') {
                    self.handle_ls_dir(
                        path,
                        false,
                        &query_params,
                        head_only,
                        user,
                        access_paths,
                        &mut res,
                    )
                    .await?;
                } else {
                    self.handle_not_found(&query_params, headers, head_only, &mut res)
                        .await?;
                }
            }
            Method::OPTIONS => {
                set_webdav_headers(&mut res);
            }
            Method::PUT => {
                if is_dir || !allow_upload || (!allow_delete && size > 0) {
                    status_forbid(&mut res);
                } else {
                    self.handle_upload(path, None, size, req, &mut res).await?;
                }
            }
            Method::PATCH => {
                if is_miss {
                    status_not_found(&mut res);
                } else if !allow_upload {
                    status_forbid(&mut res);
                } else {
                    let offset = match parse_upload_offset(headers, size) {
                        Ok(v) => v,
                        Err(err) => {
                            status_bad_request(&mut res, &err.to_string());
                            return Ok(res);
                        }
                    };
                    match offset {
                        Some(offset) => {
                            if offset < size && !allow_delete {
                                status_forbid(&mut res);
                            }
                            self.handle_upload(path, Some(offset), size, req, &mut res)
                                .await?;
                        }
                        None => {
                            *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                        }
                    }
                }
            }
            Method::DELETE => {
                if path == self.args.serve_path.as_path() {
                    status_forbid(&mut res);
                } else if !allow_remove {
                    status_forbid(&mut res);
                } else if !is_miss {
                    self.handle_delete(path, is_dir, &mut res).await?
                } else {
                    status_not_found(&mut res);
                }
            }
            method => match method.as_str() {
                "ROUTERCLOUDSAVE" => {
                    if !allow_routercloud_edit {
                        status_forbid(&mut res);
                    } else if is_miss || !is_file {
                        status_not_found(&mut res);
                    } else if size > EDITABLE_TEXT_MAX_SIZE {
                        *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                        *res.body_mut() = body_full("Payload Too Large");
                    } else {
                        self.handle_routercloud_save(path, req, &mut res).await?;
                    }
                }
                "PROPFIND" => {
                    if is_dir {
                        let access_paths =
                            if access_paths.perm().indexonly() && authorization.is_none() {
                                // see https://github.com/sigoden/dufs/issues/229
                                AccessPaths::new(AccessPerm::ReadOnly)
                            } else {
                                access_paths
                            };
                        self.handle_propfind_dir(path, headers, access_paths, &mut res)
                            .await?;
                    } else if is_file {
                        self.handle_propfind_file(path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "PROPPATCH" => {
                    if is_file {
                        self.handle_proppatch(req_path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "MKCOL" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if !is_miss {
                        *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                        *res.body_mut() = body_full("Already exists");
                    } else {
                        self.handle_mkcol(path, &mut res).await?;
                    }
                }
                "COPY" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_copy(path, &req, &mut res).await?
                    }
                }
                "MOVE" => {
                    if !allow_move {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_move(path, &req, &mut res).await?
                    }
                }
                "LOCK" => {
                    // Fake lock
                    if is_file {
                        let has_auth = authorization.is_some();
                        self.handle_lock(req_path, has_auth, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "UNLOCK" => {
                    // Fake unlock
                    if is_miss {
                        status_not_found(&mut res);
                    }
                }
                _ => {
                    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                }
            },
        }
        Ok(res)
    }

    async fn handle_upload(
        &self,
        path: &Path,
        upload_offset: Option<u64>,
        size: u64,
        req: Request,
        res: &mut Response,
    ) -> Result<()> {
        ensure_path_parent(path).await?;
        let (mut file, status) = match upload_offset {
            None => (fs::File::create(path).await?, StatusCode::CREATED),
            Some(offset) if offset == size => (
                fs::OpenOptions::new().append(true).open(path).await?,
                StatusCode::NO_CONTENT,
            ),
            Some(offset) => {
                let mut file = fs::OpenOptions::new().write(true).open(path).await?;
                file.seek(SeekFrom::Start(offset)).await?;
                (file, StatusCode::NO_CONTENT)
            }
        };
        let stream = IncomingStream::new(req.into_body());

        let body_with_io_error = stream.map_err(io::Error::other);
        let body_reader = StreamReader::new(body_with_io_error);

        pin_mut!(body_reader);

        let ret = io::copy(&mut body_reader, &mut file).await;
        let size = fs::metadata(path)
            .await
            .map(|v| v.len())
            .unwrap_or_default();
        if ret.is_err() {
            if upload_offset.is_none() && size < RESUMABLE_UPLOAD_MIN_SIZE {
                let _ = tokio::fs::remove_file(&path).await;
            }
            ret?;
        }

        *res.status_mut() = status;

        Ok(())
    }

    async fn handle_routercloud_save(
        &self,
        path: &Path,
        req: Request,
        res: &mut Response,
    ) -> Result<()> {
        let symlink_meta = fs::symlink_metadata(path).await?;

        if symlink_meta.is_symlink() {
            status_forbid(res);
            return Ok(());
        }

        let meta = fs::metadata(path).await?;

        if !meta.is_file() {
            status_not_found(res);
            return Ok(());
        }

        if meta.len() > EDITABLE_TEXT_MAX_SIZE {
            *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
            *res.body_mut() = body_full("Payload Too Large");
            return Ok(());
        }

        let mut current_probe = Vec::new();

        fs::File::open(path)
            .await?
            .take(1024)
            .read_to_end(&mut current_probe)
            .await?;

        if !content_inspector::inspect(&current_probe).is_text() {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
            *res.body_mut() = body_full("File is not editable text");
            return Ok(());
        }

        if let Some(content_length) = req.headers().get(CONTENT_LENGTH) {
            let content_length = match content_length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
            {
                Some(value) => value,
                None => {
                    status_bad_request(res, "Invalid Content-Length");
                    return Ok(());
                }
            };

            if content_length > ROUTERCLOUD_EDIT_BODY_MAX {
                *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                *res.body_mut() = body_full("Payload Too Large");
                return Ok(());
            }
        }

        let mut incoming = req.into_body();
        let mut body = Vec::new();

        while let Some(frame) = incoming.frame().await {
            let frame = frame?;

            if let Ok(data) = frame.into_data() {
                if body.len().saturating_add(data.len()) > ROUTERCLOUD_EDIT_BODY_MAX {
                    *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                    *res.body_mut() = body_full("Payload Too Large");
                    return Ok(());
                }

                body.extend_from_slice(&data);
            }
        }

        if !content_inspector::inspect(&body).is_text() {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
            *res.body_mut() = body_full("Body is not text");
            return Ok(());
        }

        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("Missing parent directory"))?;

        let temp_path = parent.join(format!(".routercloud-save-{}.tmp", Uuid::new_v4()));

        let permissions = meta.permissions();

        if let Err(err) = fs::write(&temp_path, &body).await {
            return Err(err.into());
        }

        if let Err(err) = fs::set_permissions(&temp_path, permissions).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(err.into());
        }

        if let Err(err) = fs::rename(&temp_path, path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(err.into());
        }

        status_no_content(res);
        Ok(())
    }

    async fn handle_routercloud_zip_selection(
        &self,
        dir: &Path,
        req: Request,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        let media_type = content_type.split(';').next().unwrap_or_default().trim();

        if !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;

            *res.body_mut() = body_full("Unsupported Media Type");

            return Ok(());
        }

        if let Some(content_length) = req.headers().get(CONTENT_LENGTH) {
            let content_length = match content_length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
            {
                Some(value) => value,
                None => {
                    status_bad_request(res, "Invalid Content-Length");

                    return Ok(());
                }
            };

            if content_length > ROUTERCLOUD_ZIP_SELECTION_BODY_MAX {
                *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                *res.body_mut() = body_full("Payload Too Large");

                return Ok(());
            }
        }

        let mut incoming = req.into_body();
        let mut body = Vec::new();

        while let Some(frame) = incoming.frame().await {
            let frame = frame?;

            if let Ok(data) = frame.into_data() {
                if body.len().saturating_add(data.len()) > ROUTERCLOUD_ZIP_SELECTION_BODY_MAX {
                    *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                    *res.body_mut() = body_full("Payload Too Large");

                    return Ok(());
                }

                body.extend_from_slice(&data);
            }
        }

        let selection_json = form_urlencoded::parse(&body).find_map(|(key, value)| {
            if key == "selection" {
                Some(value.into_owned())
            } else {
                None
            }
        });

        let selection_json = match selection_json {
            Some(value) => value,
            None => {
                status_bad_request(res, "Missing selection");

                return Ok(());
            }
        };

        let selection: Vec<String> = match serde_json::from_str(&selection_json) {
            Ok(value) => value,
            Err(_) => {
                status_bad_request(res, "Invalid selection");

                return Ok(());
            }
        };

        if selection.is_empty() {
            status_bad_request(res, "Empty selection");

            return Ok(());
        }

        if selection.len() > MAX_SUBPATHS_COUNT as usize {
            *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

            *res.body_mut() = body_full("Too many selected paths");

            return Ok(());
        }

        let mut unique_names = HashSet::new();
        let mut selected = Vec::new();

        for name in selection {
            if !valid_routercloud_zip_selection_path(&name) {
                status_bad_request(res, "Invalid selected path");

                return Ok(());
            }

            if !unique_names.insert(name.clone()) {
                continue;
            }

            let selected_access = match access_paths.guard(&name, &Method::GET) {
                Some(value) => value,
                None => {
                    status_forbid(res);
                    return Ok(());
                }
            };

            let selected_path = dir.join(Path::new(&name));

            if self.guard_root_contained(&selected_path).await {
                status_forbid(res);
                return Ok(());
            }

            let meta = match fs::metadata(&selected_path).await {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    status_not_found(res);
                    return Ok(());
                }
                Err(err) => return Err(err.into()),
            };

            let is_dir = meta.is_dir();
            let is_file = meta.is_file();

            if !is_dir && !is_file {
                status_bad_request(res, "Unsupported selected path");

                return Ok(());
            }

            if is_hidden(&self.args.hidden, get_file_name(&selected_path), is_dir) {
                status_not_found(res);
                return Ok(());
            }

            selected.push((selected_path, selected_access, is_dir));
        }

        if selected.is_empty() {
            status_bad_request(res, "Empty selection");

            return Ok(());
        }

        let (mut writer, reader) = tokio::io::duplex(BUF_SIZE);

        let dirname = try_get_file_name(dir)?;

        set_content_disposition(res, false, &format!("{dirname}-zaznaczone.zip"))?;

        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/zip"));

        let base_dir = dir.to_owned();
        let hidden = self.args.hidden.clone();
        let running = self.running.clone();

        let compression = self.args.compress.to_compression();

        let follow_symlinks = self.args.allow_symlink;

        let serve_path = self.args.serve_path.clone();

        tokio::spawn(async move {
            if let Err(err) = zip_selected(
                &mut writer,
                &base_dir,
                selected,
                &hidden,
                compression,
                follow_symlinks,
                serve_path,
                running,
            )
            .await
            {
                error!("Failed to zip RouterCloud selection: {err}");
            }
        });

        let reader_stream = ReaderStream::with_capacity(reader, BUF_SIZE);

        let stream_body = StreamBody::new(
            reader_stream
                .map_ok(Frame::data)
                .map_err(|err| anyhow!("{err}")),
        );

        *res.body_mut() = stream_body.boxed();

        Ok(())
    }

    async fn handle_delete(&self, path: &Path, is_dir: bool, res: &mut Response) -> Result<()> {
        match is_dir {
            true => fs::remove_dir_all(path).await?,
            false => fs::remove_file(path).await?,
        }

        status_no_content(res);
        Ok(())
    }

    async fn handle_ls_dir(
        &self,
        path: &Path,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let mut paths = vec![];
        if !head_only && exist {
            paths = match self.list_dir(path, path, access_paths.clone()).await {
                Ok(paths) => paths,
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        };
        self.send_index(
            path,
            paths,
            exist,
            query_params,
            head_only,
            user,
            access_paths,
            res,
        )
    }

    async fn handle_search_dir(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let mut paths: Vec<PathItem> = vec![];
        let search = query_params
            .get("q")
            .ok_or_else(|| anyhow!("invalid q"))?
            .to_lowercase();
        if search.is_empty() {
            return self
                .handle_ls_dir(path, true, query_params, head_only, user, access_paths, res)
                .await;
        }

        if !head_only {
            let path_buf = path.to_path_buf();
            let hidden = Arc::new(self.args.hidden.to_vec());
            let search = search.clone();

            let search_paths = tokio::spawn(collect_dir_entries(
                access_paths.clone(),
                self.running.clone(),
                path_buf,
                hidden,
                self.args.allow_symlink,
                self.args.serve_path.clone(),
                move |x| get_file_name(x.path()).to_lowercase().contains(&search),
            ))
            .await?;

            for search_path in search_paths.into_iter() {
                if let Ok(Some(item)) = self.to_pathitem(search_path, path.to_path_buf()).await {
                    paths.push(item);
                }
            }
        }
        self.send_index(
            path,
            paths,
            true,
            query_params,
            head_only,
            user,
            access_paths,
            res,
        )
    }

    async fn handle_zip_dir(
        &self,
        path: &Path,
        head_only: bool,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let (mut writer, reader) = tokio::io::duplex(BUF_SIZE);
        let filename = try_get_file_name(path)?;
        set_content_disposition(res, false, &format!("{filename}.zip"))?;
        res.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/zip"));
        if head_only {
            return Ok(());
        }
        let path = path.to_owned();
        let hidden = self.args.hidden.clone();
        let running = self.running.clone();
        let compression = self.args.compress.to_compression();
        let follow_symlinks = self.args.allow_symlink;
        let serve_path = self.args.serve_path.clone();
        tokio::spawn(async move {
            if let Err(e) = zip_dir(
                &mut writer,
                &path,
                access_paths,
                &hidden,
                compression,
                follow_symlinks,
                serve_path,
                running,
            )
            .await
            {
                error!("Failed to zip {}, {e}", path.display());
            }
        });
        let reader_stream = ReaderStream::with_capacity(reader, BUF_SIZE);
        let stream_body = StreamBody::new(
            reader_stream
                .map_ok(Frame::data)
                .map_err(|err| anyhow!("{err}")),
        );
        let boxed_body = stream_body.boxed();
        *res.body_mut() = boxed_body;
        Ok(())
    }

    async fn handle_render_index(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let index_path = path.join(INDEX_NAME);
        if fs::metadata(&index_path)
            .await
            .ok()
            .map(|v| v.is_file())
            .unwrap_or_default()
        {
            self.handle_send_file(&index_path, headers, head_only, res)
                .await?;
        } else if self.args.render_try_index {
            self.handle_ls_dir(path, true, query_params, head_only, user, access_paths, res)
                .await?;
        } else {
            self.handle_not_found(query_params, headers, head_only, res)
                .await?;
        }
        Ok(())
    }

    async fn handle_file_json(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let pathitem = match self.to_pathitem(path, &self.args.serve_path).await? {
            Some(v) => v,
            None => {
                status_not_found(res);
                return Ok(());
            }
        };
        let output = serde_json::to_string_pretty(&pathitem)?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_render_spa(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        if path.extension().is_none() {
            let path = self.args.serve_path.join(INDEX_NAME);
            self.handle_send_file(&path, headers, head_only, res)
                .await?;
        } else {
            self.handle_not_found(query_params, headers, head_only, res)
                .await?;
        }
        Ok(())
    }

    async fn handle_not_found(
        &self,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        if let Some(error_page) = &self.args.error_page {
            if !has_query_flag(query_params, "noscript") {
                self.handle_send_file(error_page, headers, head_only, res)
                    .await?;
                *res.status_mut() = StatusCode::NOT_FOUND;
                return Ok(());
            }
        }
        status_not_found(res);
        Ok(())
    }

    async fn handle_internal(
        &self,
        req_path: &str,
        headers: &HeaderMap<HeaderValue>,
        res: &mut Response,
    ) -> Result<bool> {
        if let Some(name) = req_path.strip_prefix(&self.assets_prefix) {
            match self.args.assets.as_ref() {
                Some(assets_path) => {
                    let path = assets_path.join(name);
                    if path.exists() {
                        self.handle_send_file(&path, headers, false, res).await?;
                    } else {
                        status_not_found(res);
                        return Ok(true);
                    }
                }
                None => match name {
                    "index.js" => {
                        *res.body_mut() = body_full(INDEX_JS);
                        res.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("application/javascript; charset=UTF-8"),
                        );
                    }
                    "index.css" => {
                        *res.body_mut() = body_full(INDEX_CSS);
                        res.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("text/css; charset=UTF-8"),
                        );
                    }
                    "favicon.ico" => {
                        *res.body_mut() = body_full(FAVICON_ICO);
                        res.headers_mut()
                            .insert("content-type", HeaderValue::from_static("image/x-icon"));
                    }
                    _ => {
                        status_not_found(res);
                    }
                },
            }
            res.headers_mut().insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            );
            res.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            Ok(true)
        } else if req_path == HEALTH_CHECK_PATH {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));

            *res.body_mut() = body_full(r#"{"status":"OK"}"#);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn handle_send_file(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let (file, meta) = tokio::join!(fs::File::open(path), fs::metadata(path),);
        let (mut file, meta) = (file?, meta?);
        let size = meta.len();
        let mut use_range = true;
        if let Some((etag, last_modified)) = extract_cache_headers(&meta) {
            if let Some(if_unmodified_since) = headers.typed_get::<IfUnmodifiedSince>() {
                if !if_unmodified_since.precondition_passes(last_modified.into()) {
                    *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                    return Ok(());
                }
            }
            if let Some(if_match) = headers.typed_get::<IfMatch>() {
                if !if_match.precondition_passes(&etag) {
                    *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                    return Ok(());
                }
            }
            if let Some(if_modified_since) = headers.typed_get::<IfModifiedSince>() {
                if !if_modified_since.is_modified(last_modified.into()) {
                    *res.status_mut() = StatusCode::NOT_MODIFIED;
                    return Ok(());
                }
            }
            if let Some(if_none_match) = headers.typed_get::<IfNoneMatch>() {
                if !if_none_match.precondition_passes(&etag) {
                    *res.status_mut() = StatusCode::NOT_MODIFIED;
                    return Ok(());
                }
            }

            res.headers_mut()
                .typed_insert(CacheControl::new().with_no_cache());
            res.headers_mut().typed_insert(last_modified);
            res.headers_mut().typed_insert(etag.clone());

            if headers.typed_get::<Range>().is_some() {
                use_range = headers
                    .typed_get::<IfRange>()
                    .map(|if_range| !if_range.is_modified(Some(&etag), Some(&last_modified)))
                    // Always be fresh if there is no validators
                    .unwrap_or(true);
            } else {
                use_range = false;
            }
        }

        let ranges = if use_range {
            headers.get(RANGE).map(|range| {
                range
                    .to_str()
                    .ok()
                    .and_then(|range| parse_range(range, size))
            })
        } else {
            None
        };

        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str(&get_content_type(path).await?)?,
        );

        let filename = try_get_file_name(path)?;
        set_content_disposition(res, true, filename)?;

        res.headers_mut().typed_insert(AcceptRanges::bytes());

        if let Some(ranges) = ranges {
            if let Some(ranges) = ranges {
                if ranges.len() == 1 {
                    let (start, end) = ranges[0];
                    file.seek(SeekFrom::Start(start)).await?;
                    let range_size = end - start + 1;
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let content_range = format!("bytes {start}-{end}/{size}");
                    res.headers_mut()
                        .insert(CONTENT_RANGE, content_range.parse()?);
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{range_size}").parse()?);
                    if head_only {
                        return Ok(());
                    }

                    let stream_body = StreamBody::new(
                        LengthLimitedStream::new(file, range_size as usize)
                            .map_ok(Frame::data)
                            .map_err(|err| anyhow!("{err}")),
                    );
                    let boxed_body = stream_body.boxed();
                    *res.body_mut() = boxed_body;
                } else {
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let boundary = Uuid::new_v4();
                    let mut body = Vec::new();
                    let content_type = get_content_type(path).await?;
                    for (start, end) in ranges {
                        file.seek(SeekFrom::Start(start)).await?;
                        let range_size = end - start + 1;
                        let content_range = format!("bytes {start}-{end}/{size}");
                        let part_header = format!(
                            "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: {content_range}\r\n\r\n",
                        );
                        body.extend_from_slice(part_header.as_bytes());
                        let mut buffer = vec![0; range_size as usize];
                        file.read_exact(&mut buffer).await?;
                        body.extend_from_slice(&buffer);
                        body.extend_from_slice(b"\r\n");
                    }
                    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
                    res.headers_mut().insert(
                        CONTENT_TYPE,
                        format!("multipart/byteranges; boundary={boundary}").parse()?,
                    );
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{}", body.len()).parse()?);
                    if head_only {
                        return Ok(());
                    }
                    *res.body_mut() = body_full(body);
                }
            } else {
                *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                res.headers_mut()
                    .insert(CONTENT_RANGE, format!("bytes */{size}").parse()?);
            }
        } else {
            res.headers_mut()
                .insert(CONTENT_LENGTH, format!("{size}").parse()?);
            if head_only {
                return Ok(());
            }

            let reader_stream = ReaderStream::with_capacity(file, BUF_SIZE);
            let stream_body = StreamBody::new(
                reader_stream
                    .map_ok(Frame::data)
                    .map_err(|err| anyhow!("{err}")),
            );
            let boxed_body = stream_body.boxed();
            *res.body_mut() = boxed_body;
        }
        Ok(())
    }

    async fn handle_edit_file(
        &self,
        path: &Path,
        kind: DataKind,
        head_only: bool,
        user: Option<String>,
        res: &mut Response,
    ) -> Result<()> {
        let (file, meta) = tokio::join!(fs::File::open(path), fs::metadata(path),);
        let (file, meta) = (file?, meta?);
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)
        );
        let mut buffer: Vec<u8> = vec![];
        file.take(1024).read_to_end(&mut buffer).await?;
        let editable =
            meta.len() <= EDITABLE_TEXT_MAX_SIZE && content_inspector::inspect(&buffer).is_text();
        let data = EditData {
            href,
            kind,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: self.args.allow_upload,
            allow_delete: self.args.allow_delete,
            routercloud_allow_edit: self.args.routercloud_allow_edit,
            auth: self.args.auth.has_users(),
            user,
            editable,
        };
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        let index_data = STANDARD.encode(serde_json::to_string(&data)?);
        let output = self
            .html
            .replace(
                "__ASSETS_PREFIX__",
                &format!("{}{}", self.args.uri_prefix, self.assets_prefix),
            )
            .replace("__ASSETS_REV__", &self.assets_revision)
            .replace("__INDEX_DATA__", &index_data);
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_no_cache());
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_hash_file(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let output = sha256_file(path).await?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_tokengen(
        &self,
        relative_path: &str,
        user: Option<String>,
        res: &mut Response,
    ) -> Result<()> {
        let output = self
            .args
            .auth
            .generate_token(relative_path, &user.unwrap_or_default())?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_PLAIN_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_propfind_dir(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let depth: u32 = match headers.get("depth") {
            Some(v) => match v.to_str().ok().and_then(|v| v.parse().ok()) {
                Some(0) => 0,
                Some(1) => 1,
                _ => {
                    status_bad_request(res, "Invalid depth: only 0 and 1 are allowed.");
                    return Ok(());
                }
            },
            None => 1,
        };
        let mut paths = match self.to_pathitem(path, &self.args.serve_path).await? {
            Some(v) => vec![v],
            None => vec![],
        };
        if depth == 1 {
            match self
                .list_dir(path, &self.args.serve_path, access_paths)
                .await
            {
                Ok(child) => paths.extend(child),
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        }
        let output = paths
            .iter()
            .map(|v| v.to_dav_xml(self.args.uri_prefix.as_str()))
            .fold(String::new(), |mut acc, v| {
                acc.push_str(&v);
                acc
            });
        res_multistatus(res, &output);
        Ok(())
    }

    async fn handle_propfind_file(&self, path: &Path, res: &mut Response) -> Result<()> {
        if let Some(pathitem) = self.to_pathitem(path, &self.args.serve_path).await? {
            res_multistatus(res, &pathitem.to_dav_xml(self.args.uri_prefix.as_str()));
        } else {
            status_not_found(res);
        }
        Ok(())
    }

    async fn handle_mkcol(&self, path: &Path, res: &mut Response) -> Result<()> {
        fs::create_dir_all(path).await?;
        *res.status_mut() = StatusCode::CREATED;
        Ok(())
    }

    async fn handle_copy(&self, path: &Path, req: &Request, res: &mut Response) -> Result<()> {
        let dest = match self.extract_dest(req, res) {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        let meta = fs::symlink_metadata(path).await?;
        if meta.is_dir() {
            status_forbid(res);
            return Ok(());
        }

        ensure_path_parent(&dest).await?;

        if self.guard_root_contained(&dest).await {
            status_bad_request(res, "Invalid Destination");
            return Ok(());
        }

        fs::copy(path, &dest).await?;

        status_no_content(res);
        Ok(())
    }

    async fn handle_move(&self, path: &Path, req: &Request, res: &mut Response) -> Result<()> {
        let dest = match self.extract_dest(req, res) {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        // RouterCloud safe-rename policy:
        // rename only inside the current directory.
        if path.parent() != dest.parent() {
            status_forbid(res);
            return Ok(());
        }

        if self.guard_root_contained(&dest).await {
            status_bad_request(res, "Invalid Destination");
            return Ok(());
        }

        match rename_noreplace(path, &dest).await {
            Ok(()) => status_no_content(res),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                *res.status_mut() = StatusCode::CONFLICT;
                *res.body_mut() = body_full("Destination already exists");
            }
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    async fn handle_lock(&self, req_path: &str, auth: bool, res: &mut Response) -> Result<()> {
        let token = if auth {
            format!("opaquelocktoken:{}", Uuid::new_v4())
        } else {
            Utc::now().timestamp().to_string()
        };

        res.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        res.headers_mut()
            .insert("lock-token", format!("<{token}>").parse()?);

        *res.body_mut() = body_full(format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
<D:locktoken><D:href>{token}</D:href></D:locktoken>
<D:lockroot><D:href>{req_path}</D:href></D:lockroot>
</D:activelock></D:lockdiscovery></D:prop>"#
        ));
        Ok(())
    }

    async fn handle_proppatch(&self, req_path: &str, res: &mut Response) -> Result<()> {
        let output = format!(
            r#"<D:response>
<D:href>{req_path}</D:href>
<D:propstat>
<D:prop>
</D:prop>
<D:status>HTTP/1.1 403 Forbidden</D:status>
</D:propstat>
</D:response>"#
        );
        res_multistatus(res, &output);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn send_index(
        &self,
        path: &Path,
        mut paths: Vec<PathItem>,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        if let Some(sort) = query_params.get("sort") {
            if sort == "name" {
                paths.sort_by(|v1, v2| v1.sort_by_name(v2))
            } else if sort == "mtime" {
                paths.sort_by(|v1, v2| v1.sort_by_mtime(v2))
            } else if sort == "size" {
                paths.sort_by(|v1, v2| v1.sort_by_size(v2))
            }
            if query_params
                .get("order")
                .map(|v| v == "desc")
                .unwrap_or_default()
            {
                paths.reverse()
            }
        } else {
            paths.sort_by(|v1, v2| v1.sort_by_name(v2))
        }
        if has_query_flag(query_params, "simple") {
            let output = paths
                .into_iter()
                .map(|v| {
                    let displayname = escape_str_pcdata(&v.name);
                    if v.is_dir() {
                        format!("{}/\n", displayname)
                    } else {
                        format!("{}\n", displayname)
                    }
                })
                .collect::<Vec<String>>()
                .join("");
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            res.headers_mut()
                .typed_insert(ContentLength(output.len() as u64));
            *res.body_mut() = body_full(output);
            if head_only {
                return Ok(());
            }
            return Ok(());
        }
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)
        );
        let readwrite = access_paths.perm().readwrite();
        let data = IndexData {
            kind: DataKind::Index,
            href,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: self.args.allow_upload && readwrite,
            allow_move: self.args.allow_move && readwrite,
            allow_delete: self.args.allow_delete && readwrite,
            routercloud_allow_delete: self.args.routercloud_allow_delete && readwrite,
            allow_search: self.args.allow_search,
            allow_archive: self.args.allow_archive,
            dir_exists: exist,
            auth: self.args.auth.has_users(),
            user,
            paths,
            storage: get_storage_info(&self.args.serve_path),
        };
        let output = if has_query_flag(query_params, "json") {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
            serde_json::to_string_pretty(&data)?
        } else if has_query_flag(query_params, "noscript") {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            generate_noscript_html(&data)?
        } else {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));

            let index_data = STANDARD.encode(serde_json::to_string(&data)?);
            self.html
                .replace(
                    "__ASSETS_PREFIX__",
                    &format!("{}{}", self.args.uri_prefix, self.assets_prefix),
                )
                .replace("__ASSETS_REV__", &self.assets_revision)
                .replace("__INDEX_DATA__", &index_data)
        };
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_no_cache());
        res.headers_mut().insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_routercloud_login_asset(
        &self,
        name: &str,
        headers: &HeaderMap<HeaderValue>,
        res: &mut Response,
    ) -> Result<()> {
        let Some(assets_path) = self.args.assets.as_ref() else {
            status_not_found(res);
            return Ok(());
        };

        let path = assets_path.join(name);

        if !fs::try_exists(&path).await.unwrap_or_default() {
            status_not_found(res);
            return Ok(());
        }

        self.handle_send_file(&path, headers, false, res).await?;

        routercloud_auth_no_store(res);

        Ok(())
    }

    async fn handle_routercloud_login(&self, req: Request, res: &mut Response) -> Result<()> {
        routercloud_auth_no_store(res);

        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        let media_type = content_type.split(';').next().unwrap_or_default().trim();

        if !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
            *res.body_mut() = body_full("Unsupported Media Type");
            return Ok(());
        }

        if let Some(content_length) = req.headers().get(CONTENT_LENGTH) {
            let content_length = match content_length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
            {
                Some(value) => value,
                None => {
                    status_bad_request(res, "Invalid Content-Length");
                    return Ok(());
                }
            };

            if content_length > ROUTERCLOUD_LOGIN_BODY_MAX {
                *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                *res.body_mut() = body_full("Payload Too Large");
                return Ok(());
            }
        }

        let mut incoming = req.into_body();
        let mut body = Vec::new();

        while let Some(frame) = incoming.frame().await {
            let frame = frame?;

            if let Ok(data) = frame.into_data() {
                if body.len().saturating_add(data.len()) > ROUTERCLOUD_LOGIN_BODY_MAX {
                    *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                    *res.body_mut() = body_full("Payload Too Large");
                    return Ok(());
                }

                body.extend_from_slice(&data);
            }
        }

        let fields: HashMap<String, String> = form_urlencoded::parse(&body).into_owned().collect();

        let username = fields
            .get("username")
            .map(String::as_str)
            .unwrap_or_default();

        let password = fields
            .get("password")
            .map(String::as_str)
            .unwrap_or_default();

        if username.is_empty() || password.is_empty() {
            status_bad_request(res, "Missing credentials");
            return Ok(());
        }

        if self
            .args
            .auth
            .authenticate_password(username, password)
            .is_none()
        {
            // Deliberately do not send WWW-Authenticate here.
            // A browser must not open its native Basic Auth dialog.
            *res.status_mut() = StatusCode::UNAUTHORIZED;
            *res.body_mut() = body_full("Invalid username or password");
            return Ok(());
        }

        let token = self.args.auth.generate_session_token(username)?;

        let cookie = routercloud_session_cookie(&token);

        res.headers_mut()
            .insert("set-cookie", HeaderValue::from_str(&cookie)?);

        *res.status_mut() = StatusCode::NO_CONTENT;

        Ok(())
    }

    // ROUTERCLOUD_PASSWORD_RECOVERY_V1
    async fn handle_routercloud_password_reset_request(
        &self,
        req: Request,
        res: &mut Response,
    ) -> Result<()> {
        routercloud_auth_no_store(res);

        const NEUTRAL_STATUS: StatusCode = StatusCode::NO_CONTENT;

        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        let media_type = content_type.split(';').next().unwrap_or_default().trim();

        if !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
            *res.body_mut() = body_full("Unsupported Media Type");

            return Ok(());
        }

        if let Some(content_length) = req.headers().get(CONTENT_LENGTH) {
            let content_length = match content_length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
            {
                Some(value) => value,

                None => {
                    status_bad_request(res, "Invalid Content-Length");

                    return Ok(());
                }
            };

            if content_length > ROUTERCLOUD_PASSWORD_RESET_BODY_MAX {
                *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                *res.body_mut() = body_full("Payload Too Large");

                return Ok(());
            }
        }

        let mut incoming = req.into_body();
        let mut body = Vec::new();

        while let Some(frame) = incoming.frame().await {
            let frame = frame?;

            if let Ok(data) = frame.into_data() {
                if body.len().saturating_add(data.len()) > ROUTERCLOUD_PASSWORD_RESET_BODY_MAX {
                    *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                    *res.body_mut() = body_full("Payload Too Large");

                    return Ok(());
                }

                body.extend_from_slice(&data);
            }
        }

        let fields: HashMap<String, String> = form_urlencoded::parse(&body).into_owned().collect();

        let email = fields
            .get("email")
            .map(|value| value.trim())
            .unwrap_or_default();

        if email.is_empty() || email.len() > 320 {
            status_bad_request(res, "Invalid email");

            return Ok(());
        }

        /*
         * Od tego miejsca odpowiedź pozostaje neutralna.
         * Nie ujawniamy, czy podany adres istnieje.
         */
        *res.status_mut() = NEUTRAL_STATUS;

        let Some(configured_email) = self.args.routercloud_password_recovery_email.as_deref()
        else {
            return Ok(());
        };

        let Some(configured_user) = self.args.routercloud_password_recovery_user.as_deref() else {
            return Ok(());
        };

        if !configured_email.trim().eq_ignore_ascii_case(email) {
            return Ok(());
        }

        if !self.args.auth.has_user(configured_user) {
            /*
             * Błąd konfiguracji również nie może
             * ujawniać informacji klientowi.
             */
            return Ok(());
        }

        let _reset_guard = self.routercloud_password_reset_lock.lock().await;

        let now_ms = routercloud_unix_time_ms();

        /*
         * Per-account cooldown. Klient nadal zawsze
         * otrzymuje tę samą odpowiedź HTTP.
         */
        if let Ok(Some(current)) = self.load_routercloud_password_reset(configured_user).await {
            if current.expires_at_ms > now_ms
                && now_ms.saturating_sub(current.issued_at_ms)
                    < ROUTERCLOUD_PASSWORD_RESET_COOLDOWN_MS
            {
                return Ok(());
            }
        }

        /*
         * Raw token istnieje wyłącznie w pamięci.
         *
         * W etapie SMTP zostanie przekazany bezpośrednio
         * do generatora wiadomości. Nie zapisujemy go
         * ani do pliku, ani do logów.
         */
        let (raw_token, token_sha256) = routercloud_generate_password_reset_token();

        let store = RouterCloudPasswordResetStore {
            version: ROUTERCLOUD_PASSWORD_RESET_VERSION,

            user: configured_user.to_string(),

            token_sha256,

            issued_at_ms: now_ms,

            expires_at_ms: now_ms.saturating_add(ROUTERCLOUD_PASSWORD_RESET_TTL_MS),
        };

        /*
         * Save the hash before sending the message.
         * If SMTP succeeds, the received link is already
         * backed by persistent reset state.
         */
        if let Err(err) = self
            .save_routercloud_password_reset(configured_user, &store)
            .await
        {
            log::warn!("RouterCloud password reset state write failed: {err}");

            return Ok(());
        }

        if let Err(err) = self
            .send_routercloud_password_reset_mail(configured_email, &raw_token)
            .await
        {
            /*
             * Do not leave a usable reset token behind
             * when no message was delivered.
             */
            if let Ok(path) = self.routercloud_password_reset_store_path(configured_user) {
                if let Err(remove_err) = fs::remove_file(&path).await {
                    if remove_err.kind() != std::io::ErrorKind::NotFound {
                        log::warn!("RouterCloud password reset cleanup failed");
                    }
                }
            }

            /*
             * Client response deliberately remains
             * the same neutral 204 response.
             * Never include the raw token in this log.
             */
            log::warn!("RouterCloud password reset mail delivery failed: {err}");

            return Ok(());
        }

        Ok(())
    }

    // ROUTERCLOUD_PASSWORD_RESET_SMTP_V1
    async fn send_routercloud_password_reset_mail(
        &self,
        email: &str,
        raw_token: &str,
    ) -> Result<()> {
        let mail_config = self
            .args
            .routercloud_password_recovery_mail_config
            .as_ref()
            .ok_or_else(|| {
                anyhow!("RouterCloud password recovery mail transport is not configured")
            })?;

        let reset_url = self
            .args
            .routercloud_password_recovery_reset_url
            .as_deref()
            .ok_or_else(|| anyhow!("RouterCloud password recovery reset URL is not configured"))?;

        let canonical_mail_config = fs::canonicalize(mail_config).await?;

        /*
         * SMTP credentials must never live below
         * the directory exported by RouterCloud.
         */
        if canonical_mail_config.starts_with(&self.args.serve_path) {
            return Err(anyhow!(
                "RouterCloud SMTP config must be outside serve path"
            ));
        }

        let metadata = fs::metadata(&canonical_mail_config).await?;

        if !metadata.is_file() {
            return Err(anyhow!("RouterCloud SMTP config is not a regular file"));
        }

        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode();

            if mode & 0o077 != 0 {
                return Err(anyhow!("RouterCloud SMTP config permissions are too broad"));
            }
        }

        let message = routercloud_password_reset_mail_message(email, reset_url, raw_token)?;

        /*
         * The raw token is sent through stdin.
         * It never appears in process arguments
         * or RouterCloud HTTP logs.
         */
        let mut child = Command::new("/opt/bin/curl")
            .arg("--config")
            .arg(&canonical_mail_config)
            .arg("--mail-rcpt")
            .arg(email)
            .arg("--upload-file")
            .arg("-")
            .arg("--connect-timeout")
            .arg("10")
            .arg("--max-time")
            .arg("30")
            .arg("--silent")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| anyhow!("Failed to start RouterCloud SMTP transport: {err}"))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("RouterCloud SMTP transport stdin unavailable"))?;

        stdin.write_all(message.as_bytes()).await?;

        drop(stdin);

        let status = child.wait().await?;

        if !status.success() {
            return Err(anyhow!(
                "RouterCloud SMTP transport failed with exit code {}",
                status.code().unwrap_or(-1)
            ));
        }

        Ok(())
    }

    // ROUTERCLOUD_PASSWORD_RESET_CONFIRM_V1
    async fn handle_routercloud_password_reset_confirm(
        &self,
        req: Request,
        res: &mut Response,
    ) -> Result<()> {
        routercloud_auth_no_store(res);

        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        let media_type = content_type.split(';').next().unwrap_or_default().trim();

        if !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;

            *res.body_mut() = body_full("Unsupported Media Type");

            return Ok(());
        }

        if let Some(content_length) = req.headers().get(CONTENT_LENGTH) {
            let content_length = match content_length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
            {
                Some(value) => value,

                None => {
                    status_bad_request(res, "Invalid Content-Length");

                    return Ok(());
                }
            };

            if content_length > ROUTERCLOUD_PASSWORD_RESET_BODY_MAX {
                *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                *res.body_mut() = body_full("Payload Too Large");

                return Ok(());
            }
        }

        let mut incoming = req.into_body();
        let mut body = Vec::new();

        while let Some(frame) = incoming.frame().await {
            let frame = frame?;

            if let Ok(data) = frame.into_data() {
                if body.len().saturating_add(data.len()) > ROUTERCLOUD_PASSWORD_RESET_BODY_MAX {
                    *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                    *res.body_mut() = body_full("Payload Too Large");

                    return Ok(());
                }

                body.extend_from_slice(&data);
            }
        }

        let fields: HashMap<String, String> = form_urlencoded::parse(&body).into_owned().collect();

        let token = fields
            .get("token")
            .map(|value| value.trim())
            .unwrap_or_default();

        let password = fields
            .get("password")
            .map(String::as_str)
            .unwrap_or_default();

        let password_confirm = fields
            .get("password_confirm")
            .map(String::as_str)
            .unwrap_or_default();

        if token.is_empty() || password.is_empty() || password_confirm.is_empty() {
            status_bad_request(res, "Missing reset fields");

            return Ok(());
        }

        if password != password_confirm {
            status_bad_request(res, "Passwords do not match");

            return Ok(());
        }

        if !valid_routercloud_new_password(password) {
            *res.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;

            *res.body_mut() = body_full("Password must contain 12 to 128 characters");

            return Ok(());
        }

        let Some(configured_user) = self.args.routercloud_password_recovery_user.as_deref() else {
            status_bad_request(res, "Invalid or expired reset token");

            return Ok(());
        };

        if !self.args.auth.has_user(configured_user) {
            status_bad_request(res, "Invalid or expired reset token");

            return Ok(());
        }

        /*
         * Token generation and consumption are
         * serialized inside one DUFS process.
         */
        let _reset_guard = self.routercloud_password_reset_lock.lock().await;

        let store = match self
            .load_routercloud_password_reset(configured_user)
            .await?
        {
            Some(store) => store,

            None => {
                status_bad_request(res, "Invalid or expired reset token");

                return Ok(());
            }
        };

        let now_ms = routercloud_unix_time_ms();

        if store.expires_at_ms <= now_ms
            || !routercloud_password_reset_token_matches(token, &store.token_sha256)
        {
            status_bad_request(res, "Invalid or expired reset token");

            return Ok(());
        }

        /*
         * Hash only after a valid token was proven.
         * This prevents unauthenticated callers from
         * forcing expensive password hashing.
         */
        let password_hash = hash_password_sha512(password)?;

        /*
         * Consume the token BEFORE changing the
         * credential. If a later write fails, the
         * token remains consumed and a fresh reset
         * must be requested.
         */
        let reset_path = self.routercloud_password_reset_store_path(configured_user)?;

        fs::remove_file(&reset_path).await?;

        self.save_routercloud_password_override(configured_user, &password_hash)
            .await?;

        self.args
            .auth
            .set_password_override(configured_user, password_hash)?;

        if !self.args.auth.has_password_override(configured_user) {
            return Err(anyhow!("Failed to activate RouterCloud password override"));
        }

        /*
         * Current browser cookie is removed explicitly.
         * Every other existing RouterCloud session is
         * rejected automatically because the signing
         * credential changed.
         */
        res.headers_mut().insert(
            "set-cookie",
            HeaderValue::from_static(
                "__Host-routercloud_session=; Path=/; Max-Age=0; \
HttpOnly; Secure; SameSite=Strict; \
Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            ),
        );

        *res.status_mut() = StatusCode::NO_CONTENT;

        Ok(())
    }

    fn routercloud_password_override_store_path(&self, user: &str) -> Result<PathBuf> {
        routercloud_password_override_store_path_for(&self.args.serve_path, user)
    }

    async fn save_routercloud_password_override(
        &self,
        user: &str,
        password_sha512_crypt: &str,
    ) -> Result<()> {
        if !password_sha512_crypt.starts_with("$6$") {
            return Err(anyhow!("Invalid RouterCloud password hash"));
        }

        let path = self.routercloud_password_override_store_path(user)?;

        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("RouterCloud password override path has no parent"))?;

        fs::create_dir_all(parent).await?;

        #[cfg(unix)]
        fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;

        let store = RouterCloudPasswordOverrideStore {
            version: ROUTERCLOUD_PASSWORD_OVERRIDE_VERSION,

            user: user.to_string(),

            password_sha512_crypt: password_sha512_crypt.to_string(),

            updated_at_ms: routercloud_unix_time_ms(),
        };

        let temp = parent.join(format!(".password-override-{}.tmp", Uuid::new_v4(),));

        let data = serde_json::to_vec_pretty(&store)?;

        fs::write(&temp, data).await?;

        #[cfg(unix)]
        fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600)).await?;

        if let Err(err) = fs::rename(&temp, &path).await {
            let _ = fs::remove_file(&temp).await;

            return Err(err.into());
        }

        Ok(())
    }

    fn routercloud_password_reset_store_path(&self, user: &str) -> Result<PathBuf> {
        let parent = self
            .args
            .serve_path
            .parent()
            .ok_or_else(|| anyhow!("RouterCloud serve path has no parent"))?;

        let mut hasher = Sha256::new();

        hasher.update(user.as_bytes());

        let user_id = hex::encode(hasher.finalize());

        Ok(parent
            .join(".routercloud-system")
            .join("password-reset")
            .join(format!("{user_id}.json")))
    }

    async fn load_routercloud_password_reset(
        &self,
        user: &str,
    ) -> Result<Option<RouterCloudPasswordResetStore>> {
        let path = self.routercloud_password_reset_store_path(user)?;

        if !fs::try_exists(&path).await.unwrap_or_default() {
            return Ok(None);
        }

        let data = fs::read(&path).await?;

        let store: RouterCloudPasswordResetStore = serde_json::from_slice(&data)?;

        if store.version != ROUTERCLOUD_PASSWORD_RESET_VERSION
            || store.user != user
            || store.token_sha256.len() != 64
            || store.expires_at_ms <= store.issued_at_ms
        {
            return Ok(None);
        }

        Ok(Some(store))
    }

    async fn save_routercloud_password_reset(
        &self,
        user: &str,
        store: &RouterCloudPasswordResetStore,
    ) -> Result<()> {
        let path = self.routercloud_password_reset_store_path(user)?;

        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("RouterCloud password-reset path has no parent"))?;

        fs::create_dir_all(parent).await?;

        #[cfg(unix)]
        fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;

        let temp = parent.join(format!(".password-reset-{}.tmp", Uuid::new_v4()));

        let data = serde_json::to_vec_pretty(store)?;

        fs::write(&temp, data).await?;

        #[cfg(unix)]
        fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600)).await?;

        if let Err(err) = fs::rename(&temp, &path).await {
            let _ = fs::remove_file(&temp).await;

            return Err(err.into());
        }

        Ok(())
    }

    fn routercloud_favorites_store_path(&self, user: &str) -> Result<PathBuf> {
        let parent = self
            .args
            .serve_path
            .parent()
            .ok_or_else(|| anyhow!("RouterCloud serve path has no parent"))?;

        let mut hasher = Sha256::new();
        hasher.update(user.as_bytes());

        let user_id = hex::encode(hasher.finalize());

        Ok(parent
            .join(".routercloud-system")
            .join("favorites")
            .join(format!("{user_id}.json")))
    }

    async fn load_routercloud_favorites(&self, user: &str) -> Result<RouterCloudFavoritesStore> {
        let path = self.routercloud_favorites_store_path(user)?;

        let data = match fs::read(&path).await {
            Ok(data) => data,

            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RouterCloudFavoritesStore {
                    version: ROUTERCLOUD_FAVORITES_VERSION,
                    favorites: Vec::new(),
                });
            }

            Err(err) => return Err(err.into()),
        };

        let store: RouterCloudFavoritesStore = serde_json::from_slice(&data)?;

        if store.version != ROUTERCLOUD_FAVORITES_VERSION {
            return Err(anyhow!("Unsupported RouterCloud favorites version"));
        }

        if store.favorites.len() > ROUTERCLOUD_FAVORITES_MAX {
            return Err(anyhow!("RouterCloud favorites limit exceeded"));
        }

        for favorite in &store.favorites {
            if normalize_routercloud_favorite_path(favorite).as_deref() != Some(favorite.as_str()) {
                return Err(anyhow!("Invalid path in RouterCloud favorites store"));
            }
        }

        Ok(store)
    }

    async fn save_routercloud_favorites(
        &self,
        user: &str,
        store: &RouterCloudFavoritesStore,
    ) -> Result<()> {
        let path = self.routercloud_favorites_store_path(user)?;

        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("RouterCloud favorites path has no parent"))?;

        fs::create_dir_all(parent).await?;

        #[cfg(unix)]
        fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;

        let temp_path = parent.join(format!(".favorites-{}.tmp", Uuid::new_v4()));

        let data = serde_json::to_vec(store)?;

        if let Err(err) = fs::write(&temp_path, &data).await {
            return Err(err.into());
        }

        #[cfg(unix)]
        if let Err(err) =
            fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)).await
        {
            let _ = fs::remove_file(&temp_path).await;

            return Err(err.into());
        }

        if let Err(err) = fs::rename(&temp_path, &path).await {
            let _ = fs::remove_file(&temp_path).await;

            return Err(err.into());
        }

        Ok(())
    }

    async fn handle_routercloud_favorites(&self, req: Request, res: &mut Response) -> Result<()> {
        routercloud_auth_no_store(res);

        let method = req.method().clone();

        if method != Method::GET && method != Method::POST && method != Method::DELETE {
            *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;

            res.headers_mut()
                .insert("allow", HeaderValue::from_static("GET, POST, DELETE"));

            return Ok(());
        }

        let session_token = match get_cookie_value(req.headers(), ROUTERCLOUD_SESSION_COOKIE) {
            Some(value) => value,

            None => {
                *res.status_mut() = StatusCode::UNAUTHORIZED;

                *res.body_mut() = body_full("Unauthorized");

                return Ok(());
            }
        };

        let (user, access_paths) = match self.args.auth.verify_session_token(session_token) {
            Ok((user, access_paths)) => (user, access_paths.clone()),

            Err(_) => {
                *res.status_mut() = StatusCode::UNAUTHORIZED;

                *res.body_mut() = body_full("Unauthorized");

                return Ok(());
            }
        };

        if method == Method::GET {
            let store = self.load_routercloud_favorites(&user).await?;

            let mut favorites = Vec::new();

            for favorite in store.favorites {
                if access_paths.guard(&favorite, &Method::GET).is_none() {
                    continue;
                }

                let Some(path) = self.join_path(&favorite) else {
                    continue;
                };

                if self.guard_root_contained(&path).await {
                    continue;
                }

                if !fs::try_exists(&path).await.unwrap_or_default() {
                    continue;
                }

                let item = match self.to_pathitem(&path, &self.args.serve_path).await {
                    Ok(Some(item)) => item,
                    _ => continue,
                };

                let name = Path::new(&favorite)
                    .file_name()
                    .map(|value| value.to_string_lossy().to_string())
                    .unwrap_or_else(|| favorite.clone());

                favorites.push(RouterCloudFavoriteItem {
                    path: favorite,
                    name,
                    path_type: item.path_type,
                    mtime: item.mtime,
                    size: item.size,
                });
            }

            let output = serde_json::to_string(&RouterCloudFavoritesResponse { favorites })?;

            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));

            res.headers_mut()
                .typed_insert(ContentLength(output.len() as u64));

            *res.body_mut() = body_full(output);

            return Ok(());
        }

        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        let media_type = content_type.split(';').next().unwrap_or_default().trim();

        if !media_type.eq_ignore_ascii_case("application/json") {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;

            *res.body_mut() = body_full("Expected application/json");

            return Ok(());
        }

        if let Some(content_length) = req.headers().get(CONTENT_LENGTH) {
            let content_length = match content_length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
            {
                Some(value) => value,

                None => {
                    status_bad_request(res, "Invalid Content-Length");

                    return Ok(());
                }
            };

            if content_length > ROUTERCLOUD_FAVORITES_BODY_MAX {
                *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                return Ok(());
            }
        }

        let mut incoming = req.into_body();

        let mut body = Vec::new();

        while let Some(frame) = incoming.frame().await {
            let frame = frame?;

            if let Ok(data) = frame.into_data() {
                if body.len().saturating_add(data.len()) > ROUTERCLOUD_FAVORITES_BODY_MAX {
                    *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;

                    return Ok(());
                }

                body.extend_from_slice(&data);
            }
        }

        let request: RouterCloudFavoriteRequest = match serde_json::from_slice(&body) {
            Ok(value) => value,

            Err(_) => {
                status_bad_request(res, "Invalid JSON body");

                return Ok(());
            }
        };

        let favorite = match normalize_routercloud_favorite_path(&request.path) {
            Some(value) => value,

            None => {
                status_bad_request(res, "Invalid favorite path");

                return Ok(());
            }
        };

        if access_paths.guard(&favorite, &Method::GET).is_none() {
            status_forbid(res);
            return Ok(());
        }

        let mut store = self.load_routercloud_favorites(&user).await?;

        if method == Method::POST {
            let Some(path) = self.join_path(&favorite) else {
                status_bad_request(res, "Invalid favorite path");

                return Ok(());
            };

            if self.guard_root_contained(&path).await {
                status_forbid(res);
                return Ok(());
            }

            if !fs::try_exists(&path).await.unwrap_or_default() {
                status_not_found(res);
                return Ok(());
            }

            match self.to_pathitem(&path, &self.args.serve_path).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    status_forbid(res);
                    return Ok(());
                }
                Err(err) => {
                    return Err(err);
                }
            }

            if store.favorites.iter().any(|value| value == &favorite) {
                *res.status_mut() = StatusCode::NO_CONTENT;

                return Ok(());
            }

            if store.favorites.len() >= ROUTERCLOUD_FAVORITES_MAX {
                *res.status_mut() = StatusCode::CONFLICT;

                *res.body_mut() = body_full("Favorites limit reached");

                return Ok(());
            }

            store.favorites.push(favorite);

            self.save_routercloud_favorites(&user, &store).await?;

            *res.status_mut() = StatusCode::NO_CONTENT;

            return Ok(());
        }

        let old_len = store.favorites.len();

        store.favorites.retain(|value| value != &favorite);

        if store.favorites.len() != old_len {
            self.save_routercloud_favorites(&user, &store).await?;
        }

        *res.status_mut() = StatusCode::NO_CONTENT;

        Ok(())
    }

    fn handle_routercloud_logout(&self, res: &mut Response) -> Result<()> {
        routercloud_auth_no_store(res);

        res.headers_mut().insert(
            "set-cookie",
            HeaderValue::from_static(
                "__Host-routercloud_session=; Path=/; Max-Age=0; \
HttpOnly; Secure; SameSite=Strict; \
Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            ),
        );

        *res.status_mut() = StatusCode::NO_CONTENT;

        Ok(())
    }

    fn auth_reject(&self, res: &mut Response) -> Result<()> {
        set_webdav_headers(res);

        www_authenticate(res, &self.args)?;
        *res.status_mut() = StatusCode::UNAUTHORIZED;
        Ok(())
    }

    async fn guard_root_contained(&self, path: &Path) -> bool {
        if self.args.allow_symlink {
            return false;
        }
        let path = if !fs::try_exists(path).await.unwrap_or_default() {
            match path.parent() {
                Some(parent) => parent.to_path_buf(),
                None => return true,
            }
        } else {
            path.to_path_buf()
        };
        !self.is_root_contained(path.as_path()).await
    }

    async fn is_root_contained(&self, path: &Path) -> bool {
        fs::canonicalize(path)
            .await
            .ok()
            .map(|v| v.starts_with(&self.args.serve_path))
            .unwrap_or_default()
    }

    fn extract_dest(&self, req: &Request, res: &mut Response) -> Option<PathBuf> {
        let headers = req.headers();
        let dest_path = match self
            .extract_destination_header(headers)
            .and_then(|dest| self.resolve_path(&dest))
        {
            Some(dest) => dest,
            None => {
                status_bad_request(res, "Invalid Destination");
                return None;
            }
        };

        let authorization = headers.get(AUTHORIZATION);

        let guard = if authorization.is_some() {
            self.args
                .auth
                .guard(&dest_path, req.method(), authorization, None, false)
        } else if let Some(session_token) = get_cookie_value(headers, ROUTERCLOUD_SESSION_COOKIE) {
            match self.args.auth.verify_session_token(session_token) {
                Ok((user, access_paths)) => {
                    (Some(user), access_paths.guard(&dest_path, req.method()))
                }
                Err(_) => self
                    .args
                    .auth
                    .guard(&dest_path, req.method(), None, None, false),
            }
        } else {
            self.args
                .auth
                .guard(&dest_path, req.method(), None, None, false)
        };

        match guard {
            (_, Some(_)) => {}
            _ => {
                status_forbid(res);
                return None;
            }
        };

        let dest = match self.join_path(&dest_path) {
            Some(dest) => dest,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return None;
            }
        };

        Some(dest)
    }

    fn extract_destination_header(&self, headers: &HeaderMap<HeaderValue>) -> Option<String> {
        let dest = headers.get("Destination")?.to_str().ok()?;
        let uri: Uri = dest.parse().ok()?;
        Some(uri.path().to_string())
    }

    fn resolve_path(&self, path: &str) -> Option<String> {
        let path = decode_uri(path)?;
        let path = path.trim_matches('/');
        let mut parts = vec![];
        for comp in Path::new(path).components() {
            if let Component::Normal(v) = comp {
                let v = v.to_string_lossy();
                if cfg!(windows) {
                    let chars: Vec<char> = v.chars().collect();
                    if chars.len() == 2 && chars[1] == ':' && chars[0].is_ascii_alphabetic() {
                        return None;
                    }
                }
                parts.push(v);
            } else {
                return None;
            }
        }
        let new_path = parts.join("/");
        let path_prefix = self.args.path_prefix.as_str();
        if path_prefix.is_empty() {
            return Some(new_path);
        }
        new_path
            .strip_prefix(path_prefix.trim_start_matches('/'))
            .map(|v| v.trim_matches('/').to_string())
    }

    fn join_path(&self, path: &str) -> Option<PathBuf> {
        if path.is_empty() {
            return Some(self.args.serve_path.clone());
        }
        let path = if cfg!(windows) {
            path.replace('/', "\\")
        } else {
            path.to_string()
        };
        Some(self.args.serve_path.join(path))
    }

    async fn list_dir(
        &self,
        entry_path: &Path,
        base_path: &Path,
        access_paths: AccessPaths,
    ) -> Result<Vec<PathItem>> {
        let mut paths: Vec<PathItem> = vec![];
        if access_paths.perm().indexonly() {
            for name in access_paths.child_names() {
                let entry_path = entry_path.join(name);
                self.add_pathitem(&mut paths, base_path, &entry_path).await;
            }
        } else {
            let mut rd = fs::read_dir(entry_path).await?;
            while let Ok(Some(entry)) = rd.next_entry().await {
                let entry_path = entry.path();
                self.add_pathitem(&mut paths, base_path, &entry_path).await;
            }
        }
        Ok(paths)
    }

    async fn add_pathitem(&self, paths: &mut Vec<PathItem>, base_path: &Path, entry_path: &Path) {
        let base_name = get_file_name(entry_path);
        if let Ok(Some(item)) = self.to_pathitem(entry_path, base_path).await {
            if is_hidden(&self.args.hidden, base_name, item.is_dir()) {
                return;
            }
            paths.push(item);
        }
    }

    async fn to_pathitem<P: AsRef<Path>>(&self, path: P, base_path: P) -> Result<Option<PathItem>> {
        let path = path.as_ref();
        let (meta, meta2) = tokio::join!(fs::metadata(&path), fs::symlink_metadata(&path));
        let (meta, meta2) = (meta?, meta2?);
        let is_symlink = meta2.is_symlink();
        if !self.args.allow_symlink && is_symlink && !self.is_root_contained(path).await {
            return Ok(None);
        }
        let is_dir = meta.is_dir();
        let path_type = match (is_symlink, is_dir) {
            (true, true) => PathType::SymlinkDir,
            (false, true) => PathType::Dir,
            (true, false) => PathType::SymlinkFile,
            (false, false) => PathType::File,
        };
        let mtime = match meta.modified().ok().or_else(|| meta.created().ok()) {
            Some(v) => to_timestamp(&v),
            None => 0,
        };
        let size = match path_type {
            PathType::Dir | PathType::SymlinkDir => {
                let mut count = 0;
                let mut entries = tokio::fs::read_dir(&path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let entry_path = entry.path();
                    let base_name = get_file_name(&entry_path);
                    let is_dir = entry
                        .file_type()
                        .await
                        .map(|v| v.is_dir())
                        .unwrap_or_default();
                    if is_hidden(&self.args.hidden, base_name, is_dir) {
                        continue;
                    }
                    count += 1;
                    if count >= MAX_SUBPATHS_COUNT {
                        break;
                    }
                }
                count
            }
            PathType::File | PathType::SymlinkFile => meta.len(),
        };
        let rel_path = path.strip_prefix(base_path)?;
        let name = normalize_path(rel_path);
        Ok(Some(PathItem {
            path_type,
            name,
            mtime,
            size,
        }))
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub enum DataKind {
    Index,
    Edit,
    View,
}

#[derive(Debug, Serialize)]
pub struct IndexData {
    pub href: String,
    pub kind: DataKind,
    pub uri_prefix: String,
    pub allow_upload: bool,
    pub allow_move: bool,
    pub allow_delete: bool,
    pub routercloud_allow_delete: bool,
    pub allow_search: bool,
    pub allow_archive: bool,
    pub dir_exists: bool,
    pub auth: bool,
    pub user: Option<String>,
    pub paths: Vec<PathItem>,
    pub storage: Option<StorageInfo>,
}

#[derive(Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct PathItem {
    pub path_type: PathType,
    pub name: String,
    pub mtime: u64,
    pub size: u64,
}

impl PathItem {
    pub fn is_dir(&self) -> bool {
        self.path_type == PathType::Dir || self.path_type == PathType::SymlinkDir
    }

    pub fn to_dav_xml(&self, prefix: &str) -> String {
        let mtime = match Utc.timestamp_millis_opt(self.mtime as i64) {
            LocalResult::Single(v) => format!("{}", v.format("%a, %d %b %Y %H:%M:%S GMT")),
            _ => String::new(),
        };
        let mut href = encode_uri(&format!("{}{}", prefix, &self.name));
        if self.is_dir() && !href.ends_with('/') {
            href.push('/');
        }
        let displayname = escape_str_pcdata(self.base_name());
        match self.path_type {
            PathType::Dir | PathType::SymlinkDir => format!(
                r#"<D:response>
<D:href>{href}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{displayname}</D:displayname>
<D:getlastmodified>{mtime}</D:getlastmodified>
<D:resourcetype><D:collection/></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#
            ),
            PathType::File | PathType::SymlinkFile => format!(
                r#"<D:response>
<D:href>{href}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{displayname}</D:displayname>
<D:getcontentlength>{}</D:getcontentlength>
<D:getlastmodified>{mtime}</D:getlastmodified>
<D:resourcetype></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#,
                self.size
            ),
        }
    }

    pub fn base_name(&self) -> &str {
        self.name.split('/').next_back().unwrap_or_default()
    }

    pub fn sort_by_name(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => {
                alphanumeric_sort::compare_str(self.name.to_lowercase(), other.name.to_lowercase())
            }
            v => v,
        }
    }

    pub fn sort_by_mtime(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => self.mtime.cmp(&other.mtime),
            v => v,
        }
    }

    pub fn sort_by_size(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => self.size.cmp(&other.size),
            v => v,
        }
    }
}

#[derive(Debug, Serialize, Clone, Copy, Eq, PartialEq)]
pub enum PathType {
    Dir,
    SymlinkDir,
    File,
    SymlinkFile,
}

impl PathType {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir | Self::SymlinkDir)
    }
}

impl Ord for PathType {
    fn cmp(&self, other: &Self) -> Ordering {
        let to_value = |t: &Self| -> u8 {
            if matches!(t, Self::Dir | Self::SymlinkDir) {
                0
            } else {
                1
            }
        };
        to_value(self).cmp(&to_value(other))
    }
}
impl PartialOrd for PathType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Deserialize)]
struct RouterCloudFavoriteRequest {
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RouterCloudFavoritesStore {
    version: u8,
    favorites: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RouterCloudFavoriteItem {
    path: String,
    name: String,
    path_type: PathType,
    mtime: u64,
    size: u64,
}

#[derive(Debug, Serialize)]
struct RouterCloudFavoritesResponse {
    favorites: Vec<RouterCloudFavoriteItem>,
}

#[derive(Debug, Serialize)]
struct EditData {
    href: String,
    kind: DataKind,
    uri_prefix: String,
    allow_upload: bool,
    allow_delete: bool,
    routercloud_allow_edit: bool,
    auth: bool,
    user: Option<String>,
    editable: bool,
}

fn to_timestamp(time: &SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn normalize_path<P: AsRef<Path>>(path: P) -> String {
    let path = path.as_ref().to_str().unwrap_or_default();
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

async fn ensure_path_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if fs::symlink_metadata(parent).await.is_err() {
            fs::create_dir_all(&parent).await?;
        }
    }
    Ok(())
}

fn add_cors(res: &mut Response) {
    res.headers_mut()
        .typed_insert(AccessControlAllowOrigin::ANY);
    res.headers_mut()
        .typed_insert(AccessControlAllowCredentials);
    res.headers_mut().insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("*"),
    );
    res.headers_mut().insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Authorization,*"),
    );
    res.headers_mut().insert(
        "Access-Control-Expose-Headers",
        HeaderValue::from_static("Authorization,*"),
    );
}

fn res_multistatus(res: &mut Response, content: &str) {
    *res.status_mut() = StatusCode::MULTI_STATUS;
    res.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    *res.body_mut() = body_full(format!(
        r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
{content}
</D:multistatus>"#,
    ));
}

async fn zip_selected<W: AsyncWrite + Unpin>(
    writer: &mut W,
    base_dir: &Path,
    selected: Vec<(PathBuf, AccessPaths, bool)>,
    hidden: &[String],
    compression: Compression,
    follow_symlinks: bool,
    serve_path: PathBuf,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let mut writer = ZipFileWriter::with_tokio(writer);
    let hidden = Arc::new(hidden.to_vec());
    let mut seen_paths = HashSet::new();

    for (selected_path, selected_access, is_dir) in selected {
        let zip_paths = if is_dir {
            let mut paths = vec![selected_path.clone()];

            let mut descendants = tokio::task::spawn(collect_dir_entries(
                selected_access,
                running.clone(),
                selected_path.clone(),
                hidden.clone(),
                follow_symlinks,
                serve_path.clone(),
                move |entry| {
                    entry.path().symlink_metadata().is_ok()
                        && (entry.file_type().is_file() || entry.file_type().is_dir())
                },
            ))
            .await?;

            paths.append(&mut descendants);

            paths
        } else {
            vec![selected_path]
        };

        for zip_path in zip_paths {
            if !seen_paths.insert(zip_path.clone()) {
                continue;
            }

            let meta = fs::metadata(&zip_path).await?;

            let is_dir = meta.is_dir();

            let mut filename = match zip_path
                .strip_prefix(base_dir)
                .ok()
                .and_then(|value| value.to_str())
                .map(|value| value.replace(MAIN_SEPARATOR, "/"))
            {
                Some(value) if !value.is_empty() => value,
                _ => continue,
            };

            if is_dir && !filename.ends_with('/') {
                filename.push('/');
            }

            let (datetime, mode) = get_file_mtime_and_mode(&zip_path).await?;

            let builder = ZipEntryBuilder::new(filename.into(), compression)
                .unix_permissions(mode)
                .last_modification_date(ZipDateTime::from_chrono(&datetime));

            if is_dir {
                writer.write_entry_whole(builder, &[]).await?;

                continue;
            }

            let mut file = File::open(&zip_path).await?;

            let mut file_writer = writer.write_entry_stream(builder).await?.compat_write();

            io::copy(&mut file, &mut file_writer).await?;

            file_writer.into_inner().close().await?;
        }
    }

    writer.close().await?;

    Ok(())
}

async fn zip_dir<W: AsyncWrite + Unpin>(
    writer: &mut W,
    dir: &Path,
    access_paths: AccessPaths,
    hidden: &[String],
    compression: Compression,
    follow_symlinks: bool,
    serve_path: PathBuf,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let mut writer = ZipFileWriter::with_tokio(writer);
    let hidden = Arc::new(hidden.to_vec());
    let zip_paths = tokio::task::spawn(collect_dir_entries(
        access_paths,
        running,
        dir.to_path_buf(),
        hidden,
        follow_symlinks,
        serve_path,
        move |x| x.path().symlink_metadata().is_ok() && x.file_type().is_file(),
    ))
    .await?;
    for zip_path in zip_paths.into_iter() {
        let filename = match zip_path
            .strip_prefix(dir)
            .ok()
            .and_then(|v| v.to_str())
            .map(|v| v.replace(MAIN_SEPARATOR, "/"))
        {
            Some(v) => v,
            None => continue,
        };
        let (datetime, mode) = get_file_mtime_and_mode(&zip_path).await?;
        let builder = ZipEntryBuilder::new(filename.into(), compression)
            .unix_permissions(mode)
            .last_modification_date(ZipDateTime::from_chrono(&datetime));
        let mut file = File::open(&zip_path).await?;
        let mut file_writer = writer.write_entry_stream(builder).await?.compat_write();
        io::copy(&mut file, &mut file_writer).await?;
        file_writer.into_inner().close().await?;
    }
    writer.close().await?;
    Ok(())
}

fn extract_cache_headers(meta: &Metadata) -> Option<(ETag, LastModified)> {
    let mtime = meta.modified().ok().or_else(|| meta.created().ok())?;
    let timestamp = to_timestamp(&mtime);
    let size = meta.len();
    let etag = format!(r#""{timestamp}-{size}""#).parse::<ETag>().ok()?;
    let last_modified = LastModified::from(mtime);
    Some((etag, last_modified))
}

fn get_cookie_value<'a>(headers: &'a HeaderMap<HeaderValue>, name: &str) -> Option<&'a str> {
    for header in headers.get_all("cookie").iter() {
        let Ok(value) = header.to_str() else {
            continue;
        };

        for item in value.split(';') {
            let Some((key, value)) = item.trim().split_once('=') else {
                continue;
            };

            if key == name {
                return Some(value);
            }
        }
    }

    None
}

fn routercloud_session_cookie(token: &str) -> String {
    format!(
        "{ROUTERCLOUD_SESSION_COOKIE}={token}; \
Path=/; Max-Age={ROUTERCLOUD_SESSION_MAX_AGE}; \
HttpOnly; Secure; SameSite=Strict"
    )
}

// ROUTERCLOUD_PASSWORD_RESET_CONFIRM_V1
fn valid_routercloud_new_password(password: &str) -> bool {
    let length = password.chars().count();

    (12..=128).contains(&length) && !password.contains('\0')
}

fn routercloud_password_reset_token_matches(raw_token: &str, expected_sha256: &str) -> bool {
    if raw_token.len() != 64 || !raw_token.bytes().all(|value| value.is_ascii_hexdigit()) {
        return false;
    }

    let actual = Sha256::digest(raw_token.as_bytes());

    let expected = match hex::decode(expected_sha256) {
        Ok(value) if value.len() == actual.len() => value,

        _ => return false,
    };

    let mut diff = 0u8;

    for (left, right) in actual.iter().zip(expected.iter()) {
        diff |= left ^ right;
    }

    diff == 0
}

// ROUTERCLOUD_PASSWORD_RESET_SMTP_V1
fn valid_routercloud_password_reset_url(value: &str) -> bool {
    value.starts_with("https://")
        && !value.is_empty()
        && !value.chars().any(|ch| matches!(ch, '\r' | '\n' | '#'))
}

fn routercloud_password_reset_mail_message(
    email: &str,
    reset_url: &str,
    raw_token: &str,
) -> Result<String> {
    if email.is_empty() || email.len() > 320 || email.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return Err(anyhow!("Invalid RouterCloud recovery email"));
    }

    if !valid_routercloud_password_reset_url(reset_url) {
        return Err(anyhow!("Invalid RouterCloud password reset URL"));
    }

    if raw_token.len() != 64 || !raw_token.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err(anyhow!("Invalid RouterCloud password reset token"));
    }

    let link = format!("{reset_url}#reset_token={raw_token}");

    Ok(format!(
        concat!(
            "From: RouterCloud <{email}>\\r\\n",
            "To: <{email}>\\r\\n",
            "Subject: RouterCloud - zmiana hasla\\r\\n",
            "MIME-Version: 1.0\\r\\n",
            "Content-Type: text/plain; charset=UTF-8\\r\\n",
            "Content-Transfer-Encoding: 8bit\\r\\n",
            "\\r\\n",
            "Otrzymalismy prosbe o zmiane hasla do RouterCloud.\\r\\n",
            "\\r\\n",
            "Link jest wazny przez 15 minut:\\r\\n",
            "{link}\\r\\n",
            "\\r\\n",
            "Jesli to nie Ty wyslales prosbe, zignoruj te wiadomosc.\\r\\n"
        ),
        email = email,
        link = link,
    ))
}

// ROUTERCLOUD_PASSWORD_RECOVERY_V1
fn routercloud_unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/*
 * Three independently generated UUIDv4 values provide
 * substantially more than 256 bits of input entropy.
 * SHA-256 compresses the seed into the 256-bit token.
 */
fn routercloud_generate_password_reset_token() -> (String, String) {
    let mut seed = Vec::with_capacity(16 * 3);

    for _ in 0..3 {
        seed.extend_from_slice(Uuid::new_v4().as_bytes());
    }

    let raw_token = hex::encode(Sha256::digest(&seed));

    let token_sha256 = hex::encode(Sha256::digest(raw_token.as_bytes()));

    (raw_token, token_sha256)
}

fn routercloud_auth_no_store(res: &mut Response) {
    res.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    res.headers_mut()
        .insert("pragma", HeaderValue::from_static("no-cache"));
}

fn should_redirect_to_routercloud_login(
    headers: &HeaderMap<HeaderValue>,
    method: &Method,
    authorization: Option<&HeaderValue>,
    is_microsoft_webdav: bool,
) -> bool {
    if authorization.is_some() || is_microsoft_webdav {
        return false;
    }

    if method != Method::GET && method != Method::HEAD {
        return false;
    }

    headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|item| item.trim().starts_with("text/html"))
        })
        .unwrap_or(false)
}

fn routercloud_login_redirect(res: &mut Response) {
    routercloud_auth_no_store(res);

    *res.status_mut() = StatusCode::FOUND;

    res.headers_mut()
        .insert("location", HeaderValue::from_static(ROUTERCLOUD_LOGIN_PATH));
}

fn status_forbid(res: &mut Response) {
    *res.status_mut() = StatusCode::FORBIDDEN;
    *res.body_mut() = body_full("Forbidden");
}

fn status_not_found(res: &mut Response) {
    *res.status_mut() = StatusCode::NOT_FOUND;
    *res.body_mut() = body_full("Not Found");
}

fn status_no_content(res: &mut Response) {
    *res.status_mut() = StatusCode::NO_CONTENT;
}

fn status_bad_request(res: &mut Response, body: &str) {
    *res.status_mut() = StatusCode::BAD_REQUEST;
    if !body.is_empty() {
        *res.body_mut() = body_full(body.to_string());
    }
}

fn set_content_disposition(res: &mut Response, inline: bool, filename: &str) -> Result<()> {
    let kind = if inline { "inline" } else { "attachment" };
    let filename: String = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii_control() && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let value = if filename.is_ascii() {
        HeaderValue::from_str(&format!("{kind}; filename=\"{filename}\"",))?
    } else {
        HeaderValue::from_str(&format!(
            "{kind}; filename=\"{}\"; filename*=UTF-8''{}",
            filename,
            encode_uri(&filename),
        ))?
    };
    res.headers_mut().insert(CONTENT_DISPOSITION, value);
    Ok(())
}

fn is_hidden(hidden: &[String], file_name: &str, is_dir: bool) -> bool {
    hidden.iter().any(|v| {
        if is_dir {
            if let Some(x) = v.strip_suffix('/') {
                return glob(x, file_name);
            }
        }
        glob(v, file_name)
    })
}

fn set_webdav_headers(res: &mut Response) {
    res.headers_mut().insert(
        "Allow",
        HeaderValue::from_static(
            "GET,HEAD,PUT,OPTIONS,DELETE,PATCH,PROPFIND,COPY,MOVE,CHECKAUTH,LOGOUT",
        ),
    );
    res.headers_mut()
        .insert("DAV", HeaderValue::from_static("1, 2, 3"));
}

async fn get_content_type(path: &Path) -> Result<String> {
    let mut buffer: Vec<u8> = vec![];
    fs::File::open(path)
        .await?
        .take(1024)
        .read_to_end(&mut buffer)
        .await?;
    let mime = mime_guess::from_path(path).first();
    let is_text = content_inspector::inspect(&buffer).is_text();
    let content_type = if is_text {
        let mut detector = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Allow);
        detector.feed(&buffer, buffer.len() < 1024);
        let enc = detector.guess(None, chardetng::Utf8Detection::Allow);
        let charset = format!("; charset={}", enc.name());
        match mime {
            Some(m) => format!("{m}{charset}"),
            None => format!("text/plain{charset}"),
        }
    } else {
        match mime {
            Some(m) => m.to_string(),
            None => "application/octet-stream".into(),
        }
    };
    Ok(content_type)
}

fn parse_upload_offset(headers: &HeaderMap<HeaderValue>, size: u64) -> Result<Option<u64>> {
    let value = match headers.get("x-update-range") {
        Some(v) => v,
        None => return Ok(None),
    };
    let err = || anyhow!("Invalid X-Update-Range Header");
    let value = value.to_str().map_err(|_| err())?;
    if value == "append" {
        return Ok(Some(size));
    }
    // use the first range
    let ranges = parse_range(value, size).ok_or_else(err)?;
    let (start, _) = ranges.first().ok_or_else(err)?;
    Ok(Some(*start))
}

async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn has_query_flag(query_params: &HashMap<String, String>, name: &str) -> bool {
    query_params
        .get(name)
        .map(|v| v.is_empty())
        .unwrap_or_default()
}

async fn collect_dir_entries<F>(
    access_paths: AccessPaths,
    running: Arc<AtomicBool>,
    path: PathBuf,
    hidden: Arc<Vec<String>>,
    follow_symlinks: bool,
    serve_path: PathBuf,
    include_entry: F,
) -> Vec<PathBuf>
where
    F: Fn(&DirEntry) -> bool,
{
    let mut paths: Vec<PathBuf> = vec![];
    for dir in access_paths.entry_paths(&path) {
        let mut it = WalkDir::new(&dir).follow_links(true).into_iter();
        it.next();
        while let Some(entry) = it.next() {
            if !running.load(atomic::Ordering::SeqCst) {
                break;
            }
            let entry = match entry {
                Ok(v) => v,
                Err(_) => continue,
            };
            let entry_path = entry.path();
            let base_name = get_file_name(entry_path);
            let is_dir = entry.file_type().is_dir();
            if is_hidden(&hidden, base_name, is_dir) {
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }

            if !follow_symlinks
                && !fs::canonicalize(entry_path)
                    .await
                    .ok()
                    .map(|v| v.starts_with(&serve_path))
                    .unwrap_or_default()
            {
                // We walked outside the server's root. This could only have
                // happened if we followed a symlink, and hence we only allow it
                // if allow_symlink is enabled, otherwise we skip this entry.
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }
            if !include_entry(&entry) {
                continue;
            }
            paths.push(entry_path.to_path_buf());
        }
    }
    paths
}

#[cfg(test)]
mod routercloud_session_http_tests {
    use super::*;

    #[test]
    fn test_routercloud_password_reset_token_hashing() {
        let (token_a, hash_a) = routercloud_generate_password_reset_token();

        let (token_b, hash_b) = routercloud_generate_password_reset_token();

        assert_eq!(token_a.len(), 64);
        assert_eq!(hash_a.len(), 64);

        assert_eq!(token_b.len(), 64);
        assert_eq!(hash_b.len(), 64);

        assert_ne!(token_a, token_b);
        assert_ne!(hash_a, hash_b);

        let expected = hex::encode(Sha256::digest(token_a.as_bytes()));

        assert_eq!(hash_a, expected);

        assert!(routercloud_password_reset_token_matches(&token_a, &hash_a,));

        assert!(!routercloud_password_reset_token_matches(&token_b, &hash_a,));

        assert!(!routercloud_password_reset_token_matches(
            "invalid-token",
            &hash_a,
        ));

        /*
         * Persistent state receives only the hash,
         * never the raw reset token.
         */
        let store = RouterCloudPasswordResetStore {
            version: ROUTERCLOUD_PASSWORD_RESET_VERSION,

            user: "alice".to_string(),

            token_sha256: hash_a.clone(),

            issued_at_ms: 1_000,

            expires_at_ms: 1_000 + ROUTERCLOUD_PASSWORD_RESET_TTL_MS,
        };

        let json = serde_json::to_string(&store).unwrap();

        assert!(json.contains(&hash_a));
        assert!(!json.contains(&token_a));
    }

    #[test]
    fn test_routercloud_password_reset_policy() {
        assert_eq!(ROUTERCLOUD_PASSWORD_RESET_TTL_MS, 15 * 60 * 1000);

        assert_eq!(ROUTERCLOUD_PASSWORD_RESET_COOLDOWN_MS, 60 * 1000);

        assert!(valid_routercloud_new_password("abcdefghijkl"));

        assert!(!valid_routercloud_new_password("abcdefghijk"));

        assert!(!valid_routercloud_new_password(&"a".repeat(129)));
    }

    #[test]
    fn test_routercloud_password_reset_mail_message() {
        let token = "a".repeat(64);

        let message = routercloud_password_reset_mail_message(
            "alice@example.com",
            "https://cloud.home.arpa/__routercloud/login",
            &token,
        )
        .unwrap();

        assert!(message.contains("To: <alice@example.com>"));

        assert!(message.contains(&format!(
            "https://cloud.home.arpa/__routercloud/login#reset_token={token}"
        )));

        assert!(!message.contains("?reset_token="));
    }

    #[test]
    fn test_routercloud_password_reset_mail_validation() {
        assert!(valid_routercloud_password_reset_url(
            "https://cloud.home.arpa/__routercloud/login"
        ));

        assert!(!valid_routercloud_password_reset_url(
            "http://cloud.home.arpa/__routercloud/login"
        ));

        assert!(!valid_routercloud_password_reset_url(
            "https://cloud.home.arpa/__routercloud/login#secret"
        ));

        assert!(routercloud_password_reset_mail_message(
            "alice\r\nBcc: attacker@example.com",
            "https://cloud.home.arpa/__routercloud/login",
            &"a".repeat(64),
        )
        .is_err());
    }

    #[test]
    fn test_routercloud_password_override_store_roundtrip() {
        let root =
            std::env::temp_dir().join(format!("dufs-routercloud-password-{}", Uuid::new_v4(),));

        let serve_path = root.join("cloud");

        std::fs::create_dir_all(&serve_path).unwrap();

        let hash = hash_password_sha512("new-secret-1234").unwrap();

        let path = routercloud_password_override_store_path_for(&serve_path, "alice").unwrap();

        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let store = RouterCloudPasswordOverrideStore {
            version: ROUTERCLOUD_PASSWORD_OVERRIDE_VERSION,

            user: "alice".to_string(),

            password_sha512_crypt: hash.clone(),

            updated_at_ms: 1234,
        };

        std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let loaded = load_routercloud_password_override_sync(&serve_path, "alice")
            .unwrap()
            .unwrap();

        assert_eq!(loaded.user, "alice");

        assert_eq!(loaded.password_sha512_crypt, hash);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_routercloud_zip_selection_path_validation() {
        assert!(valid_routercloud_zip_selection_path("plik.txt"));

        assert!(valid_routercloud_zip_selection_path("folder/plik.txt"));

        assert!(valid_routercloud_zip_selection_path(
            "Zażółć gęślą jaźń.txt"
        ));

        assert!(!valid_routercloud_zip_selection_path(""));

        assert!(!valid_routercloud_zip_selection_path("/etc/passwd"));

        assert!(!valid_routercloud_zip_selection_path("../secret"));

        assert!(!valid_routercloud_zip_selection_path("folder/../secret"));

        assert!(!valid_routercloud_zip_selection_path("."));

        assert!(!valid_routercloud_zip_selection_path("./plik.txt"));
    }

    #[test]
    fn test_routercloud_favorite_path_validation() {
        assert_eq!(
            normalize_routercloud_favorite_path("plik.txt"),
            Some("plik.txt".to_string())
        );

        assert_eq!(
            normalize_routercloud_favorite_path("folder/plik.txt"),
            Some("folder/plik.txt".to_string())
        );

        assert_eq!(
            normalize_routercloud_favorite_path("Zażółć gęślą/jaźń.txt"),
            Some("Zażółć gęślą/jaźń.txt".to_string())
        );

        assert_eq!(
            normalize_routercloud_favorite_path("folder//plik.txt"),
            Some("folder/plik.txt".to_string())
        );

        for invalid in [
            "",
            ".",
            "./plik.txt",
            "../secret",
            "folder/../secret",
            "/etc/passwd",
        ] {
            assert_eq!(
                normalize_routercloud_favorite_path(invalid),
                None,
                "unexpectedly accepted: {invalid}"
            );
        }
    }

    #[test]
    fn test_routercloud_cookie_parser() {
        let mut headers = HeaderMap::new();

        headers.insert(
            "cookie",
            HeaderValue::from_static("theme=dark; __Host-routercloud_session=abc123; language=pl"),
        );

        assert_eq!(
            get_cookie_value(&headers, ROUTERCLOUD_SESSION_COOKIE),
            Some("abc123")
        );

        assert_eq!(get_cookie_value(&headers, "missing"), None);
    }

    #[test]
    fn test_routercloud_session_cookie_security_flags() {
        let cookie = routercloud_session_cookie("token123");

        assert!(cookie.starts_with("__Host-routercloud_session=token123;"));

        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=43200"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));

        assert!(!cookie.contains("Domain="));
    }
}
