pub mod tuntap;
pub mod arp;
pub mod utils;
pub mod ip;
pub mod icmpv4;
pub mod tcp;
pub use crate::tuntap::*;
pub use crate::ip::*;
pub use crate::arp::*;
extern crate libc;
pub use std::ffi::CString;
pub use crate::utils::*;
fn handle_frame(nd:&mut netdev,hdr:&mut eth_hdr,buf:&mut [u8]) {
    let t = hdr.ethertype as i32;
    match t {
        libc::ETH_P_ARP => arp_incoming(nd,buf),
        libc::ETH_P_IP => ip_recv(nd,buf),
        _ => println!("Unrecognized ethertype {:?}\n", hdr.ethertype)
    }
}
fn main() {
    let mut net = netdev{addr:0,hwaddr:[0;6],netfd:0};
    net.device_init();
    loop {
        let mut buf:[u8;1500] = [0;1500];
        let rret = net.tun_read(&mut buf);
        println!("ret:{}",rret);
        if rret < 0 {
            println!("rustip:{:?}", Error::last_os_error());
        }
        let mut hdr = parse_frame_to_eth(&buf);
        handle_frame(&mut net,&mut hdr,&mut buf[14..rret as usize]);
    }
}