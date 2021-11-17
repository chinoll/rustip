// #[derive(Default)]
pub extern crate arrayref;
pub use crate::tuntap::*;
pub use std::mem;
pub use lazy_static::lazy_static;
pub use std::sync::Mutex;
pub use std::collections::HashMap;
#[derive(Copy, Clone)]
pub struct ArpCacheEntry {
    pub hwtype:u16,
    pub sip:u32,
    pub smac:[u8;6],
    pub state:u32
}
#[repr(C,packed)]
pub struct arp_hdr {
    hwtype:u16,
    protype:u16,
    hwsize:u8,
    prosize:u8,
    opcode:u16,
}
#[repr(C,packed)]
#[derive(Copy, Clone)]
pub struct arp_ipv4 {
    smac:[u8;6],
    sip:u32,
    dmac:[u8;6],
    dip:u32
}

const ARP_ETHERNET:u16 = 1;
const ARP_IPV4:u16 = 0x0800;
const ARP_REQUEST:u16 = 0x0001;
const ARP_REPLY:u16 = 0x0002;
const ARP_RESOLVE:u32 = 2;
const _ARP_WAITING:u32 = 1;

lazy_static! {
    static ref ARP_ENTRY:Mutex<HashMap<u32,ArpCacheEntry>> = Mutex::new(HashMap::new());
}
fn insert_arp_translation_table(arphdr:&arp_hdr,data:&arp_ipv4) {
    let mut arp = ArpCacheEntry {
        state:ARP_RESOLVE,
        hwtype:arphdr.hwtype,
        sip:data.sip,
        smac:[0;6]
    };
    arp.smac.copy_from_slice(&data.smac);
    ARP_ENTRY.lock().unwrap().entry(data.sip).or_insert(arp);
}

pub fn ip_to_mac(sip:u32) -> Option<[u8;6]> {
    match ARP_ENTRY.lock().unwrap().get(&sip) {
        Some(i) => Some(i.smac),
        None => None
    }

}

fn arp_reply(nd:&mut netdev,arphdr:&mut arp_hdr,arpdata:&mut arp_ipv4) {
    arpdata.dmac.copy_from_slice(&arpdata.smac);
    arpdata.dip = arpdata.sip;
    arpdata.smac.copy_from_slice(&nd.hwaddr);
    arpdata.sip = nd.addr;

    arphdr.opcode = ARP_REPLY.to_be();
    arphdr.hwtype = arphdr.hwtype.to_be();
    arphdr.protype = arphdr.protype.to_be();
    let mut frame = Vec::new();
    frame.extend_from_slice(any_as_u8_slice(arphdr));
    frame.extend_from_slice(any_as_u8_slice(arpdata));
    nd.transmit(libc::ETH_P_ARP.try_into().expect("Error"),&frame,arpdata.dip);
}

pub fn arp_incoming(nd:&mut netdev,buf:&[u8]) {
    let mut arphdr = unsafe{mem::transmute::<[u8;8],arp_hdr>(*arrayref::array_ref![buf,0,8])};
    arphdr.hwtype = arphdr.hwtype.to_be();
    arphdr.protype = arphdr.protype.to_be();
    arphdr.opcode = arphdr.opcode.to_be();
    if arphdr.hwtype != ARP_ETHERNET {
        println!("Unsupported HW type\n");
        return;
    }
    if arphdr.protype != ARP_IPV4 {
        println!("Unsupported protocol\n");
        return;
    }
    let mut arpdata = unsafe{mem::transmute::<[u8;20],arp_ipv4>(*arrayref::array_ref![buf[8..],0,20])};
    insert_arp_translation_table(&arphdr,&arpdata);
    if nd.addr != arpdata.dip {
        println!("ARP was not for us\n");
    }
    match arphdr.opcode {
        ARP_REQUEST => arp_reply(nd,&mut arphdr,&mut arpdata),
        ARP_REPLY => insert_arp_translation_table(&arphdr,&arpdata),
        _ => println!("Opcode not supported\n"),
    }
}