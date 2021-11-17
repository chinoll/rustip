pub use std::mem;
pub fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe{
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }
}
pub fn any_as_u16_slice<T: Sized>(p: &T) -> &[u16] {
    unsafe {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u16,
            ::std::mem::size_of::<T>(),
        )
    }
}
pub fn sizeof<T:Sized>() -> i32 {
    mem::size_of::<T>() as i32
}
pub fn checksum(data:&[u16],mut count:u16,s:u32) -> u16 {
    let mut sum:u32 = s;
    let mut j = 0;
    while count > 1 {
        sum += data[j] as u32;
        count -= 2;
        j += 1;
    }
    if count > 0 {
        sum += data[j] as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn tcp_checksum(data:&[u8],saddr:u32,daddr:u32,len:u16) -> u16 {
    let sum:u32 = saddr + daddr + (0x06 as u16).to_be() as u32 + len.to_be() as u32;
    if data.len() % 2 == 1{
        // odd
        println!("odd");
        let mut tmp = Vec::from(data);
        tmp.push(0 as u8);
        let (_head,body,_tail) = unsafe{tmp.as_slice().align_to::<u16>()};
        return checksum(&body,len+1,sum);
    } else {
        println!("even,{},{}",len,data.len());
        let (_head,body,_tail) = unsafe{data.align_to::<u16>()};
        return checksum(&body,len,sum);
    }
}

pub fn ip_port_tostring(addr:u32,port:u16) -> String {
    let s = format!("{}.{}.{}.{}:{}",(addr >> 24),(addr & 0xff0000) >> 16,(addr & 0x00ff00) >> 8,addr & 0x0000ff,port.to_be());
    s
}