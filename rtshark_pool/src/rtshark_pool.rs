use rtshark::{Packet, RTShark};
use std::fmt::Error;
use std::sync::mpsc::{channel, sync_channel, Receiver};
use std::thread::{JoinHandle, Thread};
use std::time::Duration;
use std::{io, thread};
use sysinfo::{Pid, PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

pub struct RTSharkPool {
    current: RTShark,
    mem_thread: JoinHandle<()>,
    recv: Receiver<RTShark>,
}

pub type CreateTShark = fn() -> io::Result<RTShark>;

impl RTSharkPool {
    pub fn new(create_rtshark: CreateTShark, mem_limit: u64) -> RTSharkPool {
        let current = create_rtshark().expect("unable to create");
        let (mem_thread, recv) = Self::mem_check_thread(
            Pid::from_u32(current.pid().unwrap()),
            create_rtshark,
            mem_limit,
        );
        RTSharkPool {
            current,
            mem_thread,
            recv,
        }
    }

    pub fn read(&mut self) -> io::Result<Option<Packet>> {
        if let Ok(rtshark) = self.recv.try_recv() {
            self.current = rtshark;
        }
        self.current.read()
    }

    fn mem_check_thread(
        pid: Pid,
        create_rtshark: CreateTShark,
        limit: u64,
    ) -> (JoinHandle<()>, Receiver<RTShark>) {
        let mut pid = Some(pid);
        let (send, recv) = channel();
        let thread = thread::spawn(move || loop {
            let mut system = System::new();
            if let Some(pid2) = pid {
                system.refresh_process_specifics(pid2, ProcessRefreshKind::new());
                if let Some(process) = system.process(pid2) {
                    if process.memory() > limit {
                        let new_rtshark = create_rtshark().expect("unable to create");
                        pid = new_rtshark.pid().map(Pid::from_u32);
                        send.send(new_rtshark).expect("unable to send");
                    }
                }
            }
            thread::sleep(Duration::from_millis(5000));
        });
        (thread, recv)
    }
}
