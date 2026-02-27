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
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::frontends::nfs::NfsServer;

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

    loop {
        let (stream, _) = listener.accept().await.expect("Failed to accept");
        let io = TokioIo::new(stream);
        let dav_server = dav_server.clone();
        let auth = auth.clone();

        tokio::spawn(async move {
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

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                error!("WebDAV connection error: {:?}", e);
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
