extern crate core;

use crate::rtshark_pool::RTSharkPool;
use rtshark::{Layer, Metadata, Packet, RTShark, RTSharkBuilder};

mod rtshark_pool;

fn main() {
    let mut pool = RTSharkPool::new(
        RTSharkBuilder::builder()
            .input_path("utun5")
            .live_capture()
            .display_filter("tls"),
        200_000,
    );
    let mut source = RTSharkBuilder::builder()
        .input_path("utun5")
        .live_capture()
        .display_filter("tls")
        .spawn()
        .unwrap();

    loop {
        if let Some(packet) = source.read().unwrap() {
            //let meta = match packet.get("tls.handshake.extensions_server_name") {
            let meta = match packet.get("frame.len") {
                None => continue,
                Some(meta) => meta,
            };
            println!("ROOT: {:?}", meta.value());
        }
        if let Some(packet) = pool.read().unwrap() {
            //let meta = match packet.get("tls.handshake.extensions_server_name") {
            let meta = match packet.get("frame.len") {
                None => continue,
                Some(meta) => meta,
            };
            println!("test: {:?}", meta.value());
        }
    }
}
