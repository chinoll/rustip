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
    pub timestamp: [u8; 9],
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
const STATUS_CLOSE_WAIT:u8 = 6;
const _STATUS_CLOSING:u8 = 7;
const _STATUS_LAST_ACK:u8 = 8;
const _STATUS_TIME_WAIT:u8 = 9;
const _STATUS_CLOSED:u8 = 10;
const STATUS_LISTEN:u8 = 11;
const STATUS_WAIT_ACK:u8 = 12;

const ACK:u8 = 0x10;
const SYN:u8 = 0x02;
const FIN:u8 = 0x01;
const RST:u8 = 0x04;
const PSH:u8 = 0x08;
const _URG:u8 = 0x20;

const PORT_OPEN:u8 = 0;
const PORT_CLOSED:u8 = 1;
lazy_static! {
    static ref TCP_STATUS_MACHINE:Mutex<HashMap<String,TcpSeqAck>> = Mutex::new(HashMap::new());
    static ref PORT_STATUS:Mutex<HashMap<u16,u8>> = Mutex::new(HashMap::new());
}
fn get_port_status(port:u16) -> u8 {
    PORT_STATUS.lock().unwrap().get(&port).unwrap_or(&PORT_CLOSED).clone()
}

fn set_port_status(port:u16,status:u8) {
    PORT_STATUS.lock().unwrap().insert(port,status);
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

fn tcp_accept(nd:&mut netdev,tcp_packet:&mut tcp,ip:u32,daddr:u32,port:u16,buf:&[u8]) {
    let ip_port = ip_port_tostring(ip.to_be(),port);
    let status = get_status(&ip_port);
    if tcp_packet.flags == SYN && status == STATUS_LISTEN {
        let dst = tcp_packet.src;
        tcp_packet.src = tcp_packet.dst;
        tcp_packet.dst = dst;
        tcp_packet.ack = (tcp_packet.seq.to_be() + 1).to_be();
        tcp_packet.checksum = 0;
        tcp_packet.offset = 0x70;

        if get_port_status(tcp_packet.src.to_be()) == PORT_OPEN {
            tcp_packet.seq = rand::thread_rng().gen_range(tcp_packet.ack..u32::max_value()).to_be();
            tcp_packet.flags = SYN | ACK;
            set_status(&ip_port, STATUS_RECV);
        } else {
            tcp_packet.seq = 0;
            tcp_packet.flags = RST | ACK;
        }
        let tcp_mss = TcpOption{kind:2,option:Option{mss:[0x04,0x05,0xb4]}};
        let tcp_wscale = TcpOption{kind:3,option:Option{wscale:[0x03,0x07]}};
        let tcp_nop = TcpOption{kind:0,option:Option{nop:0}};
        let buf = [ &any_as_u8_slice(tcp_packet),
                    &any_as_u8_slice(&tcp_mss)[..4],
                    &any_as_u8_slice(&tcp_wscale)[..3],
                    &any_as_u8_slice(&tcp_nop)[..1]].concat();
        tcp_packet.checksum = tcp_checksum(&buf,daddr,ip,28 as u16);
        let buf = [ &any_as_u8_slice(tcp_packet),
                    &any_as_u8_slice(&tcp_mss)[..4],
                    &any_as_u8_slice(&tcp_wscale)[..3],
                    &any_as_u8_slice(&tcp_nop)[..1]].concat();
        ip_send(nd,ip,IP_TCP,&buf);

    } else if tcp_packet.flags == ACK && (status == STATUS_RECV || status == STATUS_WAIT_ACK) {
        set_status(&ip_port, STATUS_ESTABLISHED);
        set_ack(&ip_port, tcp_packet.ack);
        set_seq(&ip_port, tcp_packet.seq);
    } else if tcp_packet.flags == PSH | ACK && status == STATUS_ESTABLISHED {
        let dst = tcp_packet.src;
        tcp_packet.src = tcp_packet.dst;
        tcp_packet.dst = dst;
        let data_len = buf[((tcp_packet.offset >> 4) << 2) as usize..].len() as u32;
        let ack = tcp_packet.ack;
        tcp_packet.ack = (tcp_packet.seq.to_be() + data_len).to_be();
        tcp_packet.seq = ack;
        tcp_packet.flags = ACK;
        tcp_packet.checksum = 0;
        tcp_packet.offset = 0x50;
        set_ack(&ip_port, tcp_packet.ack);
        set_seq(&ip_port, tcp_packet.seq);
        let dbuf = any_as_u8_slice(tcp_packet);
        tcp_packet.checksum = tcp_checksum(dbuf,daddr,ip,20 as u16);
        let mut dbuf = [any_as_u8_slice(tcp_packet)].concat();
        ip_send(nd,ip,IP_TCP,&dbuf);

    } else if tcp_packet.flags == FIN | ACK && status == STATUS_ESTABLISHED {
        let dst = tcp_packet.src;
        tcp_packet.src = tcp_packet.dst;
        tcp_packet.dst = dst;
        let ack = tcp_packet.ack;
        tcp_packet.ack = (tcp_packet.seq.to_be() + 1).to_be();
        tcp_packet.seq = ack;
        tcp_packet.flags = ACK;
        tcp_packet.checksum = 0;
        tcp_packet.offset = 0x50;
 
        //被动关闭
        let dbuf = any_as_u8_slice(tcp_packet);
        tcp_packet.checksum = tcp_checksum(&dbuf,daddr,ip,dbuf.len() as u16);
        let dbuf = any_as_u8_slice(tcp_packet);
        set_status(&ip_port, STATUS_CLOSE_WAIT);
        ip_send(nd,ip,IP_TCP,&dbuf);
    }
}

pub fn tcp_incoming(nd:&mut netdev,ih:&mut iphdr,buf:&mut [u8]) {
    let mut tcp = unsafe { mem::transmute::<[u8;20],tcp>(*arrayref::array_ref![buf,0,20]) };
    let tcp_opt_len = ((tcp.offset >> 4)*4 - 20) as i32;
    let tcp_opt = &buf[20..(tcp_opt_len + 20) as usize];
    let mut tcp_opt_ptr:i32 = 0;
    let ip = ih.saddr;
    let port = tcp.src.to_be();
    if tcp_checksum(buf,ih.saddr,ih.daddr,buf.len() as u16) != 0 {
        println!("TCP checksum error");
    }

    let ip_port = ip_port_tostring(ih.saddr.to_be(),port);
    init_status(&ip_port);
    set_port(&ip_port, port);
    //跳过TCP选项
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
                    tcp_opti.option.timestamp.copy_from_slice(&tcp_opt[((tcp_opt_ptr + 1) as usize)..(tcp_opt_ptr + 10) as usize]);
                    tcp_opt_ptr += 10;
                }
                _ => {
                    tcp_opt_ptr += tcp_opt[(tcp_opt_ptr + 1) as usize] as i32 - 1;
                }
            }
        }
        tcp_opt_ptr += 1;
    }
    tcp_accept(nd,&mut tcp,ip,ih.daddr,port,buf);
}

pub fn tcp_send(nd:&mut netdev,daddr:u32,src_port:u16,dst_port:u16,opt_size:u16,flags:u8,buf:&[u8]) {
    let s = *TCP_STATUS_MACHINE.lock().unwrap().get(&ip_port_tostring(daddr.to_be(),dst_port)).unwrap();
    let mut tcp_s = tcp{
        src: src_port.to_be(),
        dst: dst_port.to_be(),
        seq: s.seq,
        ack: s.ack,
        offset: ((5 + opt_size/4) << 4) as u8,
        flags: flags,
        window: (502 as u16).to_be(),
        checksum: 0,
        urg:0
    };

    let dbuf = &[any_as_u8_slice(&tcp_s),buf].concat();
    tcp_s.checksum = tcp_checksum(&dbuf,nd.addr,daddr,dbuf.len() as u16);
    let mut dbuf = [any_as_u8_slice(&tcp_s),buf].concat();
    ip_send(nd,daddr,IP_TCP,&mut dbuf);
}