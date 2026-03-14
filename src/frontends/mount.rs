use crate::cryptofs::{CryptoFs, FileSystem};
use crate::frontends::auth::WebDavAuth;
use crate::frontends::webdav::WebDav;
use dav_server::DavHandler;
use dav_server::fakels::FakeLs;
use hyper::body::Incoming;
use hyper::http::{StatusCode, header};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::frontends::nfs::NfsServer;

/// Maximum number of concurrent WebDAV TCP connections.
///
/// Each connection holds a file descriptor; capping concurrency prevents
/// FD exhaustion that would otherwise crash the accept loop with EMFILE.
/// On macOS the default per-process soft limit is 256 FDs, so the
/// combined budget (sockets + file handles + misc) must stay below that.
const MAX_WEBDAV_CONNECTIONS: usize = 64;

/// How long the server waits for a client to send request headers on a
/// keep-alive connection before closing it.  This is effectively the
/// idle timeout: after a response is sent, if no new request headers
/// arrive within this window the connection is closed, freeing its FD.
///
/// WebDAV clients (Finder, Nautilus, etc.) tend to hold many connections
/// open via keep-alive, which exhausts FDs over time without a timeout.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn mount_webdav<FS: 'static + FileSystem>(
    listen_address: String,
    crypto_fs: CryptoFs<FS>,
    auth: Option<WebDavAuth>,
) {
    let webdav = WebDav::new(crypto_fs);

    let addr: SocketAddr = listen_address
        .parse()
        .expect("Unable to parse webdav listen address");
    let dav_server = DavHandler::builder()
        .filesystem(Box::new(webdav))
        .locksystem(FakeLs::new())
        .build_handler();

    let listener = TcpListener::bind(addr).await.expect("Failed to bind");
    info!("WebDav server started on {:?}", addr);

    let conn_semaphore = Arc::new(Semaphore::new(MAX_WEBDAV_CONNECTIONS));

    loop {
        // Acquire a semaphore permit *before* accepting so that we
        // back-pressure when the connection limit is reached instead of
        // accumulating unbounded TCP sockets.
        let permit = conn_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("connection semaphore closed unexpectedly");

        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept WebDAV connection: {:?}", e);
                drop(permit);
                // Brief pause to avoid a tight error loop when FDs are
                // temporarily exhausted.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let dav_server = dav_server.clone();
        let auth = auth.clone();

        tokio::spawn(async move {
            // Keep the permit alive for the duration of the connection;
            // it is released when this task exits (normal or error).
            let _permit = permit;

            let service = service_fn(move |req: Request<Incoming>| {
                let dav_server = dav_server.clone();
                let auth = auth.clone();
                async move {
                    if let Some(auth) = auth {
                        let authenticated = req
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|val| val.to_str().ok())
                            .map(|v| auth.check(v))
                            .unwrap_or(false);

                        if !authenticated {
                            warn!("Unauthorized WebDAV access attempt detected");

                            let resp = Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header(header::WWW_AUTHENTICATE, "Basic realm=\"Cryptomator\"")
                                .body(dav_server::body::Body::from("Unauthorized"))
                                .unwrap_or_else(|e| {
                                    error!(
                                        "Failed to build 401 response with WWW-Authenticate \
                                         header, falling back to header-less 401: {:?}",
                                        e
                                    );
                                    Response::builder()
                                        .status(StatusCode::UNAUTHORIZED)
                                        .body(dav_server::body::Body::from("Unauthorized"))
                                        .expect("hardcoded header-less 401 must always pass")
                                });

                            return Ok::<_, std::convert::Infallible>(resp);
                        }
                    }
                    Ok::<_, std::convert::Infallible>(dav_server.handle(req).await)
                }
            });

            // `header_read_timeout` closes the connection when no new
            // request headers arrive within the timeout.  This is the
            // correct idle-connection timeout: it does NOT interrupt
            // active transfers, only idle keep-alive waits.
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(io, service)
                .await
            {
                // Header-read timeouts surface as errors here – that is
                // the normal lifecycle for idle keep-alive connections.
                tracing::debug!("WebDAV connection ended: {:?}", e);
            }
        });
    }
}

pub async fn mount_nfs<FS: 'static + FileSystem>(listen_address: String, crypto_fs: CryptoFs<FS>) {
    let nfs_server = NfsServer::new(crypto_fs);

    info!("Starting NFS server on {}", listen_address);

    let listener = nfsserve::tcp::NFSTcpListener::bind(&listen_address, nfs_server)
        .await
        .expect("Failed to bind NFS server");

    use nfsserve::tcp::NFSTcp;
    listener
        .handle_forever()
        .await
        .expect("Failed to start NFS server");
}
