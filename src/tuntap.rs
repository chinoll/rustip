#[warn(temporary_cstring_as_ptr)]
pub extern crate libc;
pub extern crate arrayref;

pub use ifstructs::ifreq;
pub use nix::sys::ioctl;
pub use libc::c_void;
pub use std::{io::Error,ffi::CString,mem,process::Command};
pub use crate::utils::*;
extern {
    fn netdev_init(dev:*mut netdev,addr:*const libc::c_char,hwaddr:*const libc::c_char);
}

pub const TUNSETIFF:u64 = 1074025674;
const _BUFLEN:i32 = 1500;

#[repr(C, packed)]
#[derive(Debug)]
pub struct netdev {
    pub addr:u32,
    pub hwaddr:[u8;6],
    pub netfd:i32
}
impl netdev {
    pub fn device_init(&mut self) {
        let fd = unsafe{libc::open(CString::new("/dev/net/tun").expect("CString::new failed").as_ptr(),libc::O_RDWR)};
        if fd == -1 {
            println!("open /dev/net/tun failed");
            println!("rustip:{:?}", Error::last_os_error());
            std::process::exit(1);
        }
        let mut ifr:ifreq = ifstructs::ifreq::from_name("rustip").unwrap();
        ifr.set_flags((libc::IFF_TAP | libc::IFF_NO_PI).try_into().unwrap());
        let ptr = &mut ifr as *mut _ as *mut libc::c_void;
        let ret = unsafe{libc::ioctl(fd,TUNSETIFF,ptr)};
        if ret == -1 {
            println!("rustip:{:?}", Error::last_os_error());
            std::process::exit(1);
        }
        Command::new("ip").arg("link").arg("set").arg("rustip").arg("up").status().expect("Error");
        Command::new("ip").arg("route").arg("add").arg("dev").arg("rustip").arg("10.0.0.0/24").status().expect("Error");
        Command::new("ip").arg("address").arg("add").arg("dev").arg("rustip").arg("local").arg("10.0.0.5/24").status().expect("Error");
        self.netfd = fd;
        unsafe {
            netdev_init(self,CString::new("10.0.0.4").expect("CString::new failed").as_ptr(),CString::new("00:0c:29:6d:50:25").expect("CString::new failed").as_ptr());
        }
    }
    pub fn tun_read(&mut self,buf:&mut [u8;1500]) -> i32 {
        unsafe{libc::read(self.netfd,buf as *mut _ as *mut libc::c_void,1500).try_into().unwrap()}
    }

    fn tun_write(&mut self,buf:&[u8],len:u32) -> i32 {
        unsafe{libc::write(self.netfd,buf as *const _ as *const libc::c_void,len as usize).try_into().unwrap()}
    }
    
    pub fn transmit(&mut self,hdr:&mut eth_hdr,ethertype:u16,frame:&Vec<u8>) {
        
        hdr.ethertype = ethertype.to_be();
        let smac = hdr.smac;
        hdr.smac.copy_from_slice(&self.hwaddr);
        hdr.dmac.copy_from_slice(&smac);
        let mut eth_frame = Vec::new();
        eth_frame.extend_from_slice(unsafe{any_as_u8_slice(hdr)});
        eth_frame.extend(frame);
        self.tun_write(&eth_frame,eth_frame.len() as u32);
    }
}

#[repr(C, packed)]
#[derive(Clone,Copy)]
pub struct eth_hdr {
    pub dmac:[u8;6],
    pub smac:[u8;6],
    pub ethertype:u16
}

pub fn parse_frame_to_eth(buf:&[u8]) -> eth_hdr {
    let mut ret = unsafe{mem::transmute::<[u8;14],eth_hdr>(*arrayref::array_ref![buf,0,14])};
    ret.ethertype = ret.ethertype.to_be();
    ret
}