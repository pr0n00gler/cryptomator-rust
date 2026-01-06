use crate::cryptofs::{CryptoFs, FileSystem};
use crate::frontends::auth::WebDavAuth;
use crate::frontends::webdav::WebDav;
use hyper::{header, Request, Response, StatusCode};
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{info, warn};
use webdav_handler::fakels::FakeLs;
use webdav_handler::DavHandler;

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

    let make_service = hyper::service::make_service_fn(move |_| {
        let dav_server = dav_server.clone();
        let auth = auth.clone();
        async move {
            Ok::<_, Infallible>(hyper::service::service_fn(
                move |req: Request<hyper::Body>| {
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
                                warn!("Unauthorized WebDAV access attempt from {:?}", req.uri());
                                let resp = Response::builder()
                                    .status(StatusCode::UNAUTHORIZED)
                                    .header(header::WWW_AUTHENTICATE, "Basic realm=\"Cryptomator\"")
                                    .body(webdav_handler::body::Body::from("Unauthorized"))
                                    .unwrap();
                                return Ok::<_, Infallible>(resp);
                            }
                        }
                        Ok::<_, Infallible>(dav_server.handle(req).await)
                    }
                },
            ))
        }
    });

    info!("WebDav server started on {:?}", addr);
    let _ = hyper::Server::bind(&addr)
        .serve(make_service)
        .await
        .map_err(|e| eprintln!("server error: {}", e));
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
