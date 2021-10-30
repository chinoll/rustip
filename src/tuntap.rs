pub extern crate libc;
pub extern crate arrayref;
pub use ifstructs::ifreq;
pub use nix::sys::ioctl;
pub use libc::c_void;
pub use std::{io::Error,ffi::CString,mem,process::Command};
pub const TUNSETIFF:u64 = 1074025674;
#[repr(C, packed)]
#[derive(Debug)]
pub struct netdev {
    pub addr:u32,
    pub hwaddr:[u8;6]
}
#[repr(C, packed)]
pub struct eth_hdr {
    pub dmac:[u8;6],
    pub smac:[u8;6],
    pub ethertype:u16
}

pub static mut NETFD:i32 = 0;
const _BUFLEN:i32 = 1500;
pub fn tuntap_device_init() {
    #[allow(dead_code)]
    let fd = unsafe{libc::open(CString::new("/dev/net/tun").expect("CString::new failed").as_ptr(),libc::O_RDWR)};
    if fd == -1 {
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
    unsafe {
        NETFD = fd;
    }
}
pub fn tun_read(buf:&mut [u8;200]) -> i32 {
    unsafe{libc::read(NETFD,buf as *mut _ as *mut libc::c_void,200).try_into().unwrap()}
}
pub fn tun_write(buf:&[u8],len:u32) -> i32 {
    unsafe{libc::write(NETFD,buf as *const _ as *const libc::c_void,len as usize).try_into().unwrap()}
}

pub fn init_eth_hdr(buf:&[u8]) -> eth_hdr {
    let mut ret = unsafe{mem::transmute::<[u8;14],eth_hdr>(*arrayref::array_ref![buf,0,14])};
    ret.ethertype = ret.ethertype.to_be();
    ret
}
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}
// use std::convert::TryInto;

pub fn netdev_transmit(nd:&netdev,hdr:&mut eth_hdr,ethertype:u16,frame:&[u8],dst:&[u8;6]) {
    hdr.ethertype = ethertype.to_be();
    hdr.smac.copy_from_slice(&nd.hwaddr);
    hdr.dmac.copy_from_slice(dst);
    let eth_frame = [unsafe{any_as_u8_slice(hdr)},frame].concat();
    tun_write(&eth_frame,eth_frame.len() as u32);
}