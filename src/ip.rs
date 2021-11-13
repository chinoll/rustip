extern crate libc;
pub use crate::tuntap::*;
pub use crate::icmpv4::*;
pub use crate::tuntap::*;
pub use crate::tcp::*;
#[repr(C, packed)]
pub struct iphdr {
    pub ver_and_ihl:u8,
    pub tos:u8,
    pub len:u16,
    pub id:u16,
    pub flag_and_offset:u16,
    pub ttl:u8,
    pub proto:u8,
    pub csum:u16,
    pub saddr:u32,
    pub daddr:u32
}
const IPV4:u8 = 0x04;
pub const IP_TCP:u8 = 0x06;
pub const ICMPV4:u8 = 0x01;
static mut id:u16 = 7890;
impl iphdr {
    pub fn get_verison(&mut self) -> u8 {
        (self.ver_and_ihl & 0xf0) >> 4
    }
    pub fn get_ihl(&mut self) -> u8 {
        self.ver_and_ihl & 0xf
    }
    pub fn get_flag(&mut self) -> u8 {
        (self.flag_and_offset & 0xe000) as u8
    }
    pub fn get_offset(&mut self) -> u16 {
        self.flag_and_offset & 0x1fff
    }
    pub fn set_offset(&mut self,offset:u16) {
        self.flag_and_offset = offset;
    }
    pub fn set_flag(&mut self,flag:u16) {
        self.flag_and_offset |= flag & 0xe000;
    }
    pub fn set_ihl(&mut self,ihl:u8) {
        self.ver_and_ihl = ((4 as u8) << 4) | (ihl & 0xf);
    }
}

pub fn ip_recv(nd:&mut netdev,hdr:&mut eth_hdr,buf:&mut [u8]) {
    let s = sizeof::<iphdr>() as usize;
    let mut ip_hdr = unsafe{mem::transmute::<[u8;20],iphdr>(*arrayref::array_ref![buf,0,20])};
    if ip_hdr.get_verison() != IPV4 {
        println!("Datagram version was not IPv4 {:?}\n",ip_hdr.get_verison());
        return;
    }
    if ip_hdr.get_ihl() < 5 {
        println!("IPv4 header length must be at least 5\n");
        return;
    }

    if ip_hdr.ttl == 0 {
        println!("Time to live of datagram reached 0\n");
        return;
    }
    let x = ip_hdr.get_ihl() as u16;
    if checksum(unsafe{any_as_u16_slice(&ip_hdr)},x * 4,0) != 0 {
        println!("checksum error {:?} {:?}",checksum(unsafe{any_as_u16_slice(&ip_hdr)},x * 4,0),ip_hdr.csum);
        return;
    }
    ip_hdr.len = ip_hdr.len.to_be();
    match ip_hdr.proto {
        ICMPV4 => icmpv4_incoming(nd,hdr,&mut ip_hdr,&mut buf[s..]),
        IP_TCP => tcp_incoming(nd,hdr,&mut ip_hdr,&mut buf[s..]),
        _ => println!("protoctl no!")
    }
}

pub fn ip_send(nd:&mut netdev,hdr:&mut eth_hdr,ih:&mut iphdr,buf:&mut [u8],proto:u8) {
    ih.set_ihl(0x05);
    ih.tos = 0;
    ih.len = sizeof::<iphdr>() as u16 + buf.len() as u16;
    ih.set_offset(0x4000);
    ih.ttl = 64;
    ih.proto = proto;
    unsafe{ih.id = id;}
    ih.id = ih.id.to_be();
    unsafe{id += 1;}
    let daddr = ih.saddr;
    ih.saddr = ih.daddr;
    ih.daddr = daddr;
    ih.len = ih.len.to_be();
    ih.csum = 0;
    ih.flag_and_offset = ih.flag_and_offset.to_be();
    ih.csum = checksum(unsafe{any_as_u16_slice(ih)}, 20,0);
    nd.transmit(hdr,libc::ETH_P_IP as u16,&[unsafe{any_as_u8_slice(ih)},buf].concat());
}
