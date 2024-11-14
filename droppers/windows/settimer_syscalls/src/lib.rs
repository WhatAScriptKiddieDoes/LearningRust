mod runner;
use runner::runner;

#[no_mangle]
pub unsafe fn execute() {
    runner();
}
