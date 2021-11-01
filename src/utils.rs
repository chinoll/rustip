pub use std::mem;
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}
pub unsafe fn any_as_u16_slice<T: Sized>(p: &T) -> &[u16] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u16,
        ::std::mem::size_of::<T>(),
    )
}
pub fn sizeof<T:Sized>() -> i32 {
    mem::size_of::<T>() as i32
}
pub fn checksum(data:&[u16],mut count:u16) -> u16 {
    let mut sum:u32 = 0;
    // let mut i = data.len();
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