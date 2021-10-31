pub mod tuntap;
pub mod arp;
pub mod utils;
pub use crate::tuntap::*;
pub use crate::arp::*;
extern crate libc;
pub use std::ffi::CString;

fn handle_frame(nd:&mut netdev,hdr:&mut eth_hdr,buf:&[u8]) {
    let t = hdr.ethertype as i32;
    match t {
        libc::ETH_P_ARP => arp_incoming(nd,hdr,buf),
        libc::ETH_P_IP => println!("Found IPv4\n"),
        _ => println!("Unrecognized ethertype {:?}\n", hdr.ethertype)
    }
}
fn main() {
    let mut net = netdev{addr:0,hwaddr:[0;6],netfd:0};
    // net.device_init();
    net.device_init();
    loop {
        let mut buf:[u8;200] = [0;200];
        let rret = net.tun_read(&mut buf);
        if rret < 0 {
            println!("rustip:{:?}", Error::last_os_error());
        }

        let mut hdr = parse_frame_to_eth(&buf);
        handle_frame(&mut net,&mut hdr,&buf[14..]);
    }
}
