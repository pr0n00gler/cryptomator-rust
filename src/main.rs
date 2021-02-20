use cryptomator::crypto::{Cryptor, MasterKey};
use cryptomator::cryptofs::CryptoFS;
use cryptomator::frontends::webdav::WebDav;
use cryptomator::logging::init_logger;
use cryptomator::providers::LocalFS;
use std::convert::Infallible;

use log::info;
use webdav_handler::{fakels::FakeLs, DavHandler};

#[tokio::main]
async fn main() {
    let _log = init_logger();
    let local_fs = LocalFS::new();
    let master_key =
        MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();
    let cryptor = Cryptor::new(master_key);
    let crypto_fs = CryptoFS::new("tests/test_storage/d", cryptor, local_fs).unwrap();
    let webdav = WebDav::new(crypto_fs);

    let addr = ([127, 0, 0, 1], 4919).into();

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

    info!("Listening on {:?}", addr);
    let _ = hyper::Server::bind(&addr)
        .serve(make_service)
        .await
        .map_err(|e| eprintln!("server error: {}", e));
}
