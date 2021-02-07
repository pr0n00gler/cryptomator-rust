use cryptomator::crypto::{Cryptor, MasterKey};
use cryptomator::cryptofs::CryptoFS;
use cryptomator::frontends::webdav::WebDav;
use cryptomator::providers::LocalFS;

use bytes::Bytes;
use futures01::{future::Future, stream::Stream};
use webdav_handler::DavHandler;

fn main() {
    let local_fs = LocalFS::new();
    let master_key =
        MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();
    let cryptor = Cryptor::new(master_key);
    let crypto_fs = CryptoFS::new("tests/test_storage/d", cryptor, local_fs).unwrap();
    let webdav = WebDav::new(crypto_fs);

    let addr = ([127, 0, 0, 1], 4919).into();

    let dav_server = DavHandler::new(None, Box::new(webdav), None);
    let make_service = move || {
        let dav_server = dav_server.clone();
        hyper::service::service_fn(move |req: hyper::Request<hyper::Body>| {
            let (parts, body) = req.into_parts();
            let body = body.map(Bytes::from);
            let req = http::Request::from_parts(parts, body);
            let fut = dav_server.handle(req).and_then(|resp| {
                let (parts, body) = resp.into_parts();
                let body = hyper::Body::wrap_stream(body);
                Ok(hyper::Response::from_parts(parts, body))
            });
            Box::new(fut)
        })
    };

    println!("Serving {}", addr);
    let server = hyper::Server::bind(&addr)
        .serve(make_service)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server);
}
