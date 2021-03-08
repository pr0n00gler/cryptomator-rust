use crate::cryptofs::{CryptoFS, FileSystem};
use crate::frontends::webdav::WebDav;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::net::SocketAddr;
use webdav_handler::fakels::FakeLs;
use webdav_handler::DavHandler;

#[cfg(unix)]
use crate::frontends::fuse::FUSE;

pub async fn mount_webdav<FS: 'static + FileSystem>(
    listen_address: String,
    crypto_fs: CryptoFS<FS>,
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

#[cfg(unix)]
pub fn mount_fuse<FS: FileSystem>(mountpoint: String, options: String, crypto_fs: CryptoFS<FS>) {
    let fuse_fs = FUSE::new(crypto_fs);
    let options = options
        .split_whitespace()
        .map(|o| o.as_ref())
        .collect::<Vec<&OsStr>>();
    fuse::mount(fuse_fs, &mountpoint, &options).unwrap();
}
