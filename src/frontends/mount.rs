use crate::cryptofs::{CryptoFs, FileSystem};
use crate::frontends::webdav::WebDav;
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::info;
use webdav_handler::fakels::FakeLs;
use webdav_handler::DavHandler;

use crate::frontends::nfs::NfsServer;

pub async fn mount_webdav<FS: 'static + FileSystem>(
    listen_address: String,
    crypto_fs: CryptoFs<FS>,
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
        async move {
            let func = move |req| {
                let dav_server = dav_server.clone();
                async move { Ok::<_, Infallible>(dav_server.handle(req).await) }
            };
            Ok::<_, Infallible>(hyper::service::service_fn(func))
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
