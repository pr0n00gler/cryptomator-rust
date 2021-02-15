use cryptomator::crypto::{Cryptor, MasterKey};
use cryptomator::cryptofs::CryptoFS;
use cryptomator::frontends::webdav::WebDav;
use cryptomator::logging::init_logger;
use cryptomator::providers::LocalFS;

use bytes::Bytes;
use futures01::{future::Future, stream::Stream};
use log::{error, info};
use webdav_handler::{fakels::FakeLs, DavHandler};

fn main() {
    let _log = init_logger();
    let local_fs = LocalFS::new();
    let master_key =
        MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();
    let cryptor = Cryptor::new(master_key);
    let crypto_fs = CryptoFS::new("tests/test_storage/d", cryptor, local_fs).unwrap();
    let webdav = WebDav::new(crypto_fs);

    let addr = ([127, 0, 0, 1], 4919).into();

    let dav_server = DavHandler::new(None, Box::new(webdav), Some(FakeLs::new()));
    let make_service = move || {
        let dav_server = dav_server.clone();
        hyper::service::service_fn(move |req: hyper::Request<hyper::Body>| {
            let (parts, body) = req.into_parts();
            println!("REQ {} {}", parts.method.as_str(), parts.uri.path());
            let body = body.map(Bytes::from);
            let req = http::Request::from_parts(parts, body);
            let fut = dav_server.handle(req).and_then(|resp| {
                let (parts, body) = resp.into_parts();
                println!("RESP {}", parts.status);
                let body = hyper::Body::wrap_stream(body);
                Ok(hyper::Response::from_parts(parts, body))
            });
            Box::new(fut)
        })
    };

    info!("Serving {}", addr);
    let server = hyper::Server::bind(&addr)
        .serve(make_service)
        .map_err(|e| error!("server error: {}", e));

    hyper::rt::run(server);
}
