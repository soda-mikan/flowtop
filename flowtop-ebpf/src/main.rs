#![no_std]
#![no_main]

mod accept;
mod connect;
mod maps;
mod tcp_state;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
