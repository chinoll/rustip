pub use crate::ip::*;
pub use crate::utils::*;
extern crate arrayref;

#[repr(C,packed)]
#[derive(Clone,Copy)]
pub struct icmpv4 {
    icmp_type:u8,
    code:u8,
    csum:u16
}
#[repr(C,packed)]
pub struct icmpv4_echo {
    id:u16,
    seq:u16
}
const ICMP_V4_ECHO:u8 = 0x08;
const ICMP_V4_REPLY:u8 = 0x00;

pub fn icmpv4_incoming(nd:&mut netdev,hdr:&mut eth_hdr,ih:&mut iphdr,buf:&mut [u8]) {
    let mut icmp_frame = unsafe{mem::transmute::<[u8;4],icmpv4>(*arrayref::array_ref![buf,0,4])};
    match icmp_frame.icmp_type {
        ICMP_V4_ECHO => icmpv4_reply(nd,hdr,ih,&mut icmp_frame,&mut buf[4..]),
        _ => println!("Error!")
    }
}

pub fn icmpv4_reply(nd:&mut netdev,hdr:&mut eth_hdr,ih:&mut iphdr,icmp:&mut icmpv4,buf:&mut [u8]) {
    icmp.code = 0;
    icmp.csum = 0;
    icmp.icmp_type = ICMP_V4_REPLY;
    let (_head,body,_tail) = unsafe{buf.align_to::<u16>()};
    icmp.csum = checksum(&[&unsafe{mem::transmute::<icmpv4,[u16;2]>(*icmp)},body].concat(), ih.len - (ih.get_ihl() as u16 * 4));

    let icmp_echo = unsafe{mem::transmute::<icmpv4,[u16;2]>(*icmp)};
    ih.proto = ICMPV4;
    let mut frame = [unsafe{any_as_u8_slice(&icmp_echo)},buf].concat();
    ip_send(nd,hdr,ih,&mut frame);
}