extern crate core;

use crate::rtshark_pool::RTSharkPool;
use rtshark::{Layer, Metadata, Packet, RTShark, RTSharkBuilder};

mod rtshark_pool;

fn main() {
    let mut pool = RTSharkPool::new(
        || {
            RTSharkBuilder::builder()
                .input_path("en0")
                .extra_opts("-I")
                .live_capture()
                .display_filter("tls.handshake.extension.type")
                .spawn()
        },
        500000,
    );

    loop {
        if let Some(packet) = pool.read().unwrap() {
            let layer = match packet.layer_name("tls") {
                None => continue,
                Some(l) => l,
            };
            let meta = match layer.metadata("tls.handshake.extensions_server_name") {
                None => continue,
                Some(m) => m,
            };
            println!("{:?}", meta.display());
        }
    }
}
