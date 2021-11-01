// #[derive(Default)]
pub extern crate arrayref;
pub use crate::tuntap::*;
pub use std::mem;

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

const ARP_CACHE_LEN:u32 = 32;
const ARP_ETHERNET:u16 = 1;
const ARP_IPV4:u16 = 0x0800;
const ARP_REQUEST:u16 = 0x0001;
const ARP_REPLY:u16 = 0x0002;
const ARP_FREE:u32 = 0;
const ARP_RESOLVE:u32 = 2;
const _ARP_WAITING:u32 = 1;

static mut ARP_ENTRY:[ArpCacheEntry;ARP_CACHE_LEN as usize]=[ArpCacheEntry{hwtype:0,sip:0,smac:[0;6],state:0};ARP_CACHE_LEN as usize];
fn update_arp_translation_table(hdr:&arp_hdr,data:&arp_ipv4) -> u32 {
    let mut i:u32 = 0;
    unsafe {
        while i < ARP_CACHE_LEN {
            if ARP_ENTRY[i as usize].state == ARP_FREE {
                i += 1;
                continue;
            }
            if ARP_ENTRY[i as usize].hwtype == hdr.hwtype && ARP_ENTRY[i as usize].sip == data.sip {
                ARP_ENTRY[i as usize].smac.copy_from_slice(&data.smac);
                return 1;
            }
            i += 1;
        }
    }
    0
}
fn insert_arp_translation_table(arphdr:&arp_hdr,data:&arp_ipv4) -> i32 {
    let mut i:u32 = 0;
    unsafe {
        while i < ARP_CACHE_LEN {
            if ARP_ENTRY[i as usize].state == ARP_FREE {
                ARP_ENTRY[i as usize].state = ARP_RESOLVE;
                ARP_ENTRY[i as usize].hwtype = arphdr.hwtype;
                ARP_ENTRY[i as usize].sip = data.sip;
                ARP_ENTRY[i as usize].smac.copy_from_slice(&data.smac);
                return 0;
            }
            i += 1;
        }
    }
    -1
}

pub fn arp_reply(nd:&mut netdev,hdr:&mut eth_hdr,arphdr:&mut arp_hdr,arpdata:&mut arp_ipv4) {
    arpdata.dmac.copy_from_slice(&arpdata.smac);
    arpdata.dip = arpdata.sip;
    arpdata.smac.copy_from_slice(&nd.hwaddr);
    arpdata.sip = nd.addr;

    arphdr.opcode = ARP_REPLY.to_be();
    arphdr.hwtype = arphdr.hwtype.to_be();
    arphdr.protype = arphdr.protype.to_be();
    let mut frame = Vec::new();
    frame.extend_from_slice(unsafe{any_as_u8_slice(arphdr)});
    frame.extend_from_slice(unsafe{any_as_u8_slice(arpdata)});
    nd.transmit(hdr,libc::ETH_P_ARP.try_into().expect("Error"),&frame);
}

pub fn arp_incoming(nd:&mut netdev,hdr:&mut eth_hdr,buf:&[u8]) {
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
    let merge = update_arp_translation_table(&arphdr,&arpdata);
    if nd.addr != arpdata.dip {
        println!("ARP was not for us\n");
    }
    if merge == 0 &&  insert_arp_translation_table(&arphdr,&arpdata) != 0 {
        println!("ERR: No free space in ARP translation table\n");
        return;
    }
    match arphdr.opcode {
        ARP_REQUEST => arp_reply(nd,hdr,&mut arphdr,&mut arpdata),
        _ => println!("Opcode not supported\n"),
    }
}