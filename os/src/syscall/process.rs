//! Process management syscalls

use crate::{
    config::MAX_SYSCALL_NUM,
    mm::{PageTable, PhysAddr},
    task::{
        change_program_brk, current_task_mmmap, current_task_unmmap, current_user_token,
        exit_current_and_run_next, get_current_task_status, get_current_task_syscall_times,
        get_current_task_time, suspend_current_and_run_next, TaskStatus,
    },
    timer::{ get_time_us, get_time_ms},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let va = crate::mm::VirtAddr(_ts as usize);
    let vpn = va.floor();
    let ppn = PageTable::from_token(current_user_token())
        .translate(vpn)
        .unwrap()
        .ppn();
    let t = PhysAddr::from(ppn).0 + va.page_offset();
    let us = get_time_us();
    unsafe {
        *(t as *mut TimeVal) = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    let va = crate::mm::VirtAddr(_ti as usize);
    let t: usize = PhysAddr::from(
        PageTable::from_token(current_user_token())
            .translate(va.floor())
            .unwrap()
            .ppn(),
    )
    .0 + va.page_offset();
    let src = TaskInfo {
        status: get_current_task_status(),
        syscall_times: get_current_task_syscall_times(),
        time: get_time_ms() - get_current_task_time(),
    };
    unsafe {
        (t as *mut TaskInfo).write_volatile(src);
    }
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    if current_task_mmmap(_start, _len, _port) {
        return 0;
    } else {
        return -1;
    }
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    if _start & 0xfff != 0 {
        return -1;
    }
    if current_task_unmmap(_start, _len) {
        return 0;
    } else {
        return -1;
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
