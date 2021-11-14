pub use crate::ip::*;
pub use crate::utils::*;
extern crate arrayref;
pub use rand::Rng;
pub use lazy_static::lazy_static;
pub use std::sync::Mutex;
pub use std::{thread, time::Duration};
pub use std::collections::HashMap;

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
pub union Option {
    pub eol: u8,
    pub nop: u8,
    pub mss:[u8;3],
    pub wscale: [u8;2],
    pub timestamp: [u8; 10],
}
pub struct TcpOption {
    pub kind: u8,
    pub option: Option
}
#[derive(Copy,Clone,Debug)]
pub struct TcpSeqAck {
    seq:u32,
    ack:u32,
    status:u8,
    port:u16
}
const STATUS_RECV:u8 = 1;
const _STATUS_SYN_SEND:u8 = 2;
const STATUS_ESTABLISHED:u8 = 3;
const _STATUS_FIN_WAIT_1:u8 = 4;
const _STATUS_FIN_WAIT_2:u8 = 5;
const _STATUS_CLOSE_WAIT:u8 = 6;
const _STATUS_CLOSING:u8 = 7;
const _STATUS_LAST_ACK:u8 = 8;
const _STATUS_TIME_WAIT:u8 = 9;
const _STATUS_CLOSED:u8 = 10;
const STATUS_LISTEN:u8 = 11;
const STATUS_WAIT_ACK:u8 = 12;

const ACK:u8 = 0x10;
const SYN:u8 = 0x02;
const FIN:u8 = 0x01;
const _RST:u8 = 0x04;
const PSH:u8 = 0x08;
const _URG:u8 = 0x20;
const _SYN_ACK:u8 = 0x12;
lazy_static! {
    static ref TCP_STATUS_MACHINE:Mutex<HashMap<String,TcpSeqAck>> = Mutex::new(HashMap::new());
}
fn get_status(s:&String) -> u8 {
    TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap().status
}
fn set_status(s:&String,status:u8) {
    let mut map = *TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap();
    map.status = status;
    TCP_STATUS_MACHINE.lock().unwrap().insert(s.to_string(),map);
}
fn init_status(s:&String) {
    TCP_STATUS_MACHINE.lock().unwrap().entry(s.to_string()).or_insert(TcpSeqAck{seq:0,ack:0,status:STATUS_LISTEN,port:0});
}
fn set_seq(s:&String,seq:u32) {
    let mut map = *TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap();
    map.seq = seq;
    TCP_STATUS_MACHINE.lock().unwrap().insert(s.to_string(),map);
}
fn set_ack(s:&String,ack:u32) {
    let mut map = *TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap();
    map.ack = ack;
    TCP_STATUS_MACHINE.lock().unwrap().insert(s.to_string(),map);
}
fn get_seq(s:&String) -> u32 {
    TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap().seq
}
fn get_ack(s:&String) -> u32 {
    TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap().ack
}
fn set_port(s:&String,port:u16) {
    let mut p = *(TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap());
    p.port = port;
    TCP_STATUS_MACHINE.lock().unwrap().insert(s.to_string(),p);
}
fn get_port(s:&String) -> u16 {
    TCP_STATUS_MACHINE.lock().unwrap().get(s).unwrap().port
}

pub fn tcp_incoming(nd:&mut netdev,ih:&mut iphdr,buf:&mut [u8]) {
    let mut tcp = unsafe { mem::transmute::<[u8;20],tcp>(*arrayref::array_ref![buf,0,20]) };
    let tcp_opt_len = ((tcp.offset >> 4)*4 - 20) as i32;
    let tcp_opt = &buf[20..(tcp_opt_len + 20) as usize];
    let mut tcp_opt_ptr:i32 = 0;
    let (_head,body,_tail) = unsafe{buf.align_to::<u16>()};
    let ip = ih.saddr;
    let port = tcp.src.to_be();
    if tcp_checksum(body, ih.saddr, ih.daddr, buf.len() as u16) != 0 {
        println!("TCP checksum error");
        return;
    }
    let ip_port = ip_port_tostring(ih.saddr.to_be(),port);
    init_status(&ip_port);
    set_port(&ip_port, port);
    let mut timestamp = [0u8;10];
    while tcp_opt_ptr < tcp_opt_len {
        let mut tcp_opti = Box::new(TcpOption{kind:0,option:Option{eol:0}});
        unsafe {
            match tcp_opt[tcp_opt_ptr as usize] {
                1 => {
                    tcp_opti.option.eol = 0;
                }
                0 => {
                    tcp_opti.option.nop = 0;
                }
                2 => {
                    tcp_opti.option.mss = [tcp_opt[tcp_opt_ptr as usize],tcp_opt[(tcp_opt_ptr + 1) as usize],tcp_opt[(tcp_opt_ptr + 2) as usize]];
                    tcp_opt_ptr += 3;
                }
                3 => {
                    tcp_opti.option.wscale = [tcp_opt[(tcp_opt_ptr) as usize],tcp_opt[(tcp_opt_ptr+1) as usize]];
                    tcp_opt_ptr += 2;
                }
                8 => {
                    tcp_opti.option.timestamp.copy_from_slice(&tcp_opt[(tcp_opt_ptr as usize)..(tcp_opt_ptr + 10) as usize]);
                    timestamp.copy_from_slice(&tcp_opt[(tcp_opt_ptr as usize)..(tcp_opt_ptr + 10) as usize]);
                    tcp_opt_ptr += 10;
                }
                _ => {
                    tcp_opt_ptr += tcp_opt[(tcp_opt_ptr + 1) as usize] as i32 - 1;
                }
            }
        }
        tcp_opt_ptr += 1;
    }
    let status = get_status(&ip_port);

    if tcp.flags == SYN && status == STATUS_LISTEN {
        let dst = tcp.src;
        tcp.src = tcp.dst;
        tcp.dst = dst;
        tcp.ack = (tcp.seq.to_be() + 1).to_be();
        tcp.seq = rand::thread_rng().gen_range(tcp.ack..u32::max_value()).to_be();
        tcp.checksum = 0;
        tcp.flags = SYN | ACK;
        let buf = [&unsafe{any_as_u8_slice(&tcp)},&buf[20..]].concat();
        let (_head,body,_tail) = unsafe{buf.align_to::<u16>()};

        tcp.checksum = tcp_checksum(body,ih.daddr,ih.saddr,((tcp.offset >> 4) << 2) as u16);
        let mut buf = [&unsafe{any_as_u8_slice(&tcp)},&buf[20..]].concat();
        set_status(&ip_port, STATUS_RECV);
        ip_send(nd,ih.saddr,IP_TCP,&mut buf);

    } else if tcp.flags == ACK && (status == STATUS_RECV || status == STATUS_WAIT_ACK) {
        set_status(&ip_port, STATUS_ESTABLISHED);
        set_ack(&ip_port, tcp.ack);
        set_seq(&ip_port, tcp.seq);
    } else if tcp.flags == PSH | ACK && status == STATUS_ESTABLISHED {
        let dst = tcp.src;
        tcp.src = tcp.dst;
        tcp.dst = dst;
        let data_len = buf[((tcp.offset >> 4)*4) as usize..].len() as u32;
        let ack = tcp.ack;
        tcp.ack = (tcp.seq.to_be() + data_len).to_be();
        tcp.seq = ack;
        tcp.flags = ACK;
        tcp.checksum = 0;
        set_ack(&ip_port, tcp.ack);
        set_seq(&ip_port, tcp.seq);
        let dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        let (_head,body,_tail) = unsafe{dbuf.align_to::<u16>()};
        tcp.checksum = tcp_checksum(body,ih.daddr,ih.saddr,dbuf.len() as u16);
        let mut dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        ip_send(nd,ip,IP_TCP,&mut dbuf);
        let buf = "test".as_bytes();
        tcp_send(nd,ip,&buf,port,&mut timestamp);
    } else if tcp.flags == FIN | ACK && status == STATUS_ESTABLISHED {
        let dst = tcp.src;
        tcp.src = tcp.dst;
        tcp.dst = dst;
        let ack = tcp.ack;
        tcp.ack = (tcp.seq.to_be() + 1).to_be();
        tcp.seq = ack;
        tcp.flags = ACK;
        tcp.checksum = 0;
        //被动关闭
        let dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        let (_head,body,_tail) = unsafe{dbuf.align_to::<u16>()};
        tcp.checksum = tcp_checksum(body,ih.daddr,ip,dbuf.len() as u16);
        let mut dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        set_status(&ip_port, STATUS_LISTEN);
        ip_send(nd,ip,IP_TCP,&mut dbuf);

        //主动关闭
        tcp.flags = FIN | ACK;
        let dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        let (_head,body,_tail) = unsafe{dbuf.align_to::<u16>()};
        tcp.checksum = tcp_checksum(body,ih.daddr,ip,dbuf.len() as u16);
        let mut dbuf = [unsafe{any_as_u8_slice(&tcp)},tcp_opt].concat();
        ip_send(nd,ip,IP_TCP,&mut dbuf);
    }
}

pub fn tcp_send(nd:&mut netdev,daddr:u32,buf:&[u8],port:u16,timestamp:&[u8]) {
    let s = *TCP_STATUS_MACHINE.lock().unwrap().get(&ip_port_tostring(daddr.to_be(),port)).unwrap();
    let mut tcp_s = tcp{
        src: (80 as u16).to_be(),
        dst: s.port.to_be(),
        seq: s.seq,
        ack: s.ack,
        offset: 0x80,
        flags: ACK | PSH,
        window: (502 as u16).to_be(),
        checksum: 0,
        urg:0
    };
    let nop = [1u8;2];
    let dbuf = &[unsafe{any_as_u8_slice(&tcp_s)},&nop,timestamp,buf].concat();
    let (_head,body,_tail) = unsafe{dbuf.align_to::<u16>()};
    tcp_s.checksum = tcp_checksum(body,nd.addr,daddr,dbuf.len() as u16);
    let mut dbuf = [unsafe{any_as_u8_slice(&tcp_s)},&nop,timestamp,buf].concat();
    ip_send(nd,daddr,IP_TCP,&mut dbuf);
}