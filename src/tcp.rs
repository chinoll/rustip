pub use crate::ip::*;
pub use crate::utils::*;
use std::collections::HashMap;
extern crate arrayref;
pub use rand::Rng;
use lazy_static::lazy_static;
use std::sync::Mutex;

#[repr(C,packed)]
#[derive(Debug)]
pub struct tcp {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    pub ack: u32,
    pub offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urg: u16,
}
pub union option {
    pub eol: u8,
    pub nop: u8,
    pub mss:[u8;3],
    pub wscale: [u8;2],
    pub timestamp: [u8; 10],
}
pub struct tcp_option {
    pub kind: u8,
    pub option: option
}

const STATUS_RECV:u8 = 1;
const STATUS_SYN_SEND:u8 = 2;
const STATUS_ESTABLISHED:u8 = 3;
const STATUS_FIN_WAIT_1:u8 = 4;
const STATUS_FIN_WAIT_2:u8 = 5;
const STATUS_CLOSE_WAIT:u8 = 6;
const STATUS_CLOSING:u8 = 7;
const STATUS_LAST_ACK:u8 = 8;
const STATUS_TIME_WAIT:u8 = 9;
const STATUS_CLOSED:u8 = 10;
const STATUS_LISTEN:u8 = 11;

const ACK:u8 = 0x10;
const SYN:u8 = 0x02;
const FIN:u8 = 0x01;
const RST:u8 = 0x04;
const PSH:u8 = 0x08;
const URG:u8 = 0x20;
const SYN_ACK:u8 = 0x12;
lazy_static! {
    static ref tcp_status_machine:Mutex<HashMap<String,u8>> = Mutex::new(HashMap::new());
}
fn get_status(s:&String) -> u8 {
    *tcp_status_machine.lock().unwrap().get(s).unwrap()
}
fn set_status(s:String,status:u8) {
    tcp_status_machine.lock().unwrap().insert(s,status);
}
fn set_status2(s:String,status:u8) {
    tcp_status_machine.lock().unwrap().entry(s).or_insert(status);
}
pub fn tcp_incoming(nd:&mut netdev,hdr:&mut eth_hdr,ih:&mut iphdr,buf:&mut [u8]) {
    let mut tcp = unsafe { mem::transmute::<[u8;20],tcp>(*arrayref::array_ref![buf,0,20]) };
    let mut tcp_opt_len = ((tcp.offset >> 4)*4 - 20) as i32;
    let mut tcp_opt = &buf[20..(tcp_opt_len + 20) as usize];
    let mut tcp_opt_ptr:i32 = 0;
    let (_head,body,_tail) = unsafe{buf.align_to::<u16>()};
    if tcp_checksum(body, ih.saddr, ih.daddr, buf.len() as u16) != 0 {
        println!("TCP checksum error");
        return;
    }

    while tcp_opt_ptr < tcp_opt_len {
        let mut tcp_opti = Box::new(tcp_option{kind:0,option:option{eol:0}});
        unsafe {
            // println!("{}",tcp_opt[tcp_opt_ptr as usize]);
            match tcp_opt[tcp_opt_ptr as usize] {
                1 => {
                    tcp_opti.option.eol = 0;
                    // println!("EOL");
                }
                0 => {
                    tcp_opti.option.nop = 0;
                    // println!("NOP");
                }
                2 => {
                    tcp_opti.option.mss = [tcp_opt[tcp_opt_ptr as usize],tcp_opt[(tcp_opt_ptr + 1) as usize],tcp_opt[(tcp_opt_ptr + 2) as usize]];
                    tcp_opt_ptr += 3;
                    // println!("MSS");
                }
                3 => {
                    tcp_opti.option.wscale = [tcp_opt[(tcp_opt_ptr) as usize],tcp_opt[(tcp_opt_ptr+1) as usize]];
                    tcp_opt_ptr += 2;
                    // println!("WSCALE");
                }
                8 => {
                    tcp_opti.option.timestamp.copy_from_slice(&tcp_opt[(tcp_opt_ptr as usize)..(tcp_opt_ptr + 10) as usize]);
                    tcp_opt_ptr += 10;
                    // println!("TIMESTAMP");
                }
                _ => {
                    tcp_opt_ptr += tcp_opt[(tcp_opt_ptr + 1) as usize] as i32 - 1;
                    // println!("UNKNOWN");
                }
            }
        }
        tcp_opt_ptr += 1;
    }
    set_status2(ip_port_tostring(ih.saddr.to_be(),tcp.src.to_be()), STATUS_LISTEN);
    if tcp.flags == SYN && get_status(&ip_port_tostring(ih.saddr.to_be(),tcp.src.to_be())) == STATUS_LISTEN {
        let dst = tcp.src;
        tcp.src = tcp.dst;
        tcp.dst = dst;
        tcp.ack = (tcp.seq.to_be() + 1).to_be();
        tcp.seq = rand::thread_rng().gen::<u32>();
        tcp.checksum = 0;
        tcp.flags = SYN | ACK;
        let buf = [&unsafe{any_as_u8_slice(&tcp)},&buf[20..]].concat();
        let (_head,body,_tail) = unsafe{buf.align_to::<u16>()};

        tcp.checksum = tcp_checksum(body,ih.daddr,ih.saddr,((tcp.offset >> 4) << 2) as u16);
        let mut buf = [&unsafe{any_as_u8_slice(&tcp)},&buf[20..]].concat();
        set_status(ip_port_tostring(ih.saddr.to_be(),tcp.dst.to_be()), STATUS_RECV);
        ip_send(nd, hdr, ih, &mut buf, IP_TCP);
    } else if tcp.flags == ACK && get_status(&ip_port_tostring(ih.saddr.to_be(),tcp.src.to_be())) == STATUS_RECV {
        set_status(ip_port_tostring(ih.saddr.to_be(),tcp.src.to_be()), STATUS_ESTABLISHED);
    } else if tcp.flags == PSH | ACK && get_status(&ip_port_tostring(ih.saddr.to_be(),tcp.src.to_be())) == STATUS_ESTABLISHED {
        let dst = tcp.src;
        tcp.src = tcp.dst;
        tcp.dst = dst;
        let data_len = buf[((tcp.offset >> 4)*4) as usize..].len() as u32;
        let ack = tcp.ack;
        tcp.ack = (tcp.seq.to_be() + data_len).to_be();
        tcp.seq = ack;
        tcp.flags = ACK;
        tcp.checksum = 0;
        let dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        let (_head,body,_tail) = unsafe{dbuf.align_to::<u16>()};
        tcp.checksum = tcp_checksum(body,ih.daddr,ih.saddr,dbuf.len() as u16);
        let mut dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        ip_send(nd,hdr,ih,&mut dbuf,IP_TCP);
    }
}