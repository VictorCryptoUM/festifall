use rtshark::{Packet, RTShark, RTSharkBuilderReady};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt::Error;
use std::ops::Deref;
use std::ptr::eq;
use std::sync::mpsc::{channel, sync_channel, Receiver};
use std::thread::{current, JoinHandle, Thread};
use std::time::Duration;
use std::{io, thread};
use sysinfo::{Pid, PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

struct PacketOrd(Packet);

impl PacketOrd {
    fn time_epoch(&self) -> f64 {
        self.get("frame.time_epoch")
            .unwrap()
            .value()
            .parse()
            .unwrap()
    }
}

impl Deref for PacketOrd {
    type Target = Packet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Eq for PacketOrd {}

impl PartialEq<Self> for PacketOrd {
    fn eq(&self, other: &Self) -> bool {
        self.time_epoch() == other.time_epoch()
    }
}

impl PartialOrd<Self> for PacketOrd {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.time_epoch().partial_cmp(&other.time_epoch())
    }
}

impl Ord for PacketOrd {
    fn cmp(&self, other: &Self) -> Ordering {
        self.time_epoch().partial_cmp(&other.time_epoch()).unwrap()
    }
}

pub struct RTSharkPool {
    current: RTShark,
    mem_thread: JoinHandle<()>,
    recv: Receiver<RTShark>,
    buffer: Vec<PacketOrd>,
}

fn packet_equal(a: &Packet, b: &Packet) -> bool {
    let fields_to_check = ["frame.len"];
    for field in fields_to_check {
        let a_value = a.get(field).unwrap().value();
        let b_value = b.get(field).unwrap().value();
        if a_value != b_value {
            println!("C: {} != R: {}", a_value, b_value);
            return false;
        }
        println!("C: {} == R: {}", a_value, b_value);
    }
    true
}

impl RTSharkPool {
    pub fn new(builder: RTSharkBuilderReady<'static>, mem_limit: u64) -> RTSharkPool {
        let current = builder.clone().spawn().expect("unable to create");
        let (mem_thread, recv) =
            Self::mem_check_thread(Pid::from_u32(current.pid().unwrap()), builder, mem_limit);
        RTSharkPool {
            current,
            mem_thread,
            recv,
            buffer: Default::default(),
        }
    }

    pub fn replace(&mut self, mut replacement: RTShark) {
        self.buffer.clear();

        let mut read_amount = 1;
        let mut last_replacement_pkt = Some(replacement.read().unwrap().unwrap());
        let mut last_current_pkt = Some(self.current.read().unwrap().unwrap());
        loop {
            let equal = packet_equal(
                last_current_pkt.as_ref().unwrap(),
                last_replacement_pkt.as_ref().unwrap(),
            );

            if read_amount % 2 == 0 {
                self.buffer
                    .push(PacketOrd(last_replacement_pkt.take().unwrap()));
            } else {
                self.buffer
                    .push(PacketOrd(last_current_pkt.take().unwrap()));
            }

            if equal {
                break;
            }

            for _ in 0..read_amount - 1 {
                if read_amount % 2 == 0 {
                    let pkt = PacketOrd(replacement.read().unwrap().unwrap());
                    println!("LOOP | R: {:?}", pkt.get("frame.len").unwrap().value());
                    self.buffer.push(pkt);
                } else {
                    let pkt = PacketOrd(self.current.read().unwrap().unwrap());
                    println!("LOOP | C: {:?}", pkt.get("frame.len").unwrap().value());
                    self.buffer.push(pkt);
                }
            }

            if read_amount % 2 == 0 {
                last_replacement_pkt = Some(replacement.read().unwrap().unwrap());
            } else {
                last_current_pkt = Some(self.current.read().unwrap().unwrap());
            }

            read_amount += 1;
        }
        self.buffer.sort();

        println!("replace!");
        self.buffer.iter().for_each(|p| {
            println!(
                "BUFFER: {:?} - {:?}",
                p.get("frame.len").unwrap().value(),
                p.time_epoch()
            );
        });

        self.current = replacement;
    }

    pub fn read(&mut self) -> io::Result<Option<Packet>> {
        if let Ok(rtshark) = self.recv.try_recv() {
            self.replace(rtshark);
        }
        if self.buffer.is_empty() {
            self.current.read()
        } else {
            Ok(Some(self.buffer.remove(0).0))
        }
    }

    fn mem_check_thread(
        pid: Pid,
        builder: RTSharkBuilderReady<'static>,
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
                        let new_rtshark = builder.clone().spawn().expect("unable to create");
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
