pub mod tuntap;
pub mod arp;
pub use crate::tuntap::*;
pub use crate::arp::*;
extern crate libc;
pub use std::ffi::CString;

extern {
    fn netdev_init(dev:*mut netdev,addr:*const libc::c_char,fd:libc::c_int);
}
fn handle_frame(nd:&mut netdev,hdr:&mut eth_hdr,buf:&[u8]) {
    let t = hdr.ethertype as i32;
    match t {
        libc::ETH_P_ARP => arp_incoming(nd,hdr,buf),
        libc::ETH_P_IP => println!("Found IPv4\n"),
        _ => println!("Unrecognized ethertype {:?}\n", hdr.ethertype)
    }
}
fn main() {
    let mut net = Box::new(netdev{addr:0,hwaddr:[0;6]});
    println!("{:?}",*net);
    unsafe {
        tuntap_device_init();
        netdev_init(&mut *net,CString::new("10.0.0.4").expect("CString::new failed").as_ptr(),NETFD);
        println!("{:?}",*net);
    }
    loop {
        let mut buf:[u8;200] = [0;200];
        let rret = tun_read(&mut buf);
        if rret < 0 {
            println!("rustip:{:?}", Error::last_os_error());
        }
        let mut hdr = init_eth_hdr(&buf);
        handle_frame(&mut *net,&mut hdr,&buf[14..]);
    }
}
