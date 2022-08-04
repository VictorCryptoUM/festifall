use rtshark::{Packet, RTShark, RTSharkBuilderReady};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
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
    buffer: Vec<PacketOrd>,
    system: System,
    mem_limit: u64,
    builder: RTSharkBuilderReady<'static>,
}

fn packet_equal(a: &Packet, b: &Packet) -> bool {
    let fields_to_check = ["frame.len"];
    for field in fields_to_check {
        let a_value = a.get(field).unwrap().value();
        let b_value = b.get(field).unwrap().value();
        if a_value != b_value {
            //   println!("C: {} != R: {}", a_value, b_value);
            return false;
        }
        //  println!("C: {} == R: {}", a_value, b_value);
    }
    true
}

impl RTSharkPool {
    pub fn new(builder: RTSharkBuilderReady<'static>, mem_limit: u64) -> RTSharkPool {
        let current = builder.clone().spawn().expect("unable to create");
        RTSharkPool {
            current,
            buffer: Default::default(),
            system: System::new(),
            builder,
            mem_limit,
        }
    }

    pub fn replace(&mut self, mut replacement: RTShark) {
        println!("\t\t\tReplacing RTShark");
        let target = replacement.read().unwrap().unwrap();
        let mut attempt = self.current.read().unwrap().unwrap();

        while !packet_equal(&attempt, &target) {
            println!(
                "\t\t\t\tNOT EQUAL: {} - {} != {} - {}",
                attempt.get("frame.len").unwrap().value(),
                attempt.get("frame.time_epoch").unwrap().value(),
                target.get("frame.len").unwrap().value(),
                target.get("frame.time_epoch").unwrap().value()
            );
            self.buffer.push(PacketOrd(attempt));
            attempt = self.current.read().unwrap().unwrap();
        }

        self.buffer.push(PacketOrd(target));
        self.current = replacement;
    }

    pub fn read(&mut self) -> io::Result<Option<Packet>> {
        if let Some(rtshark) = self.mem_check() {
            self.replace(rtshark);
        }
        if self.buffer.is_empty() {
            self.current.read()
        } else {
            Ok(Some(self.buffer.remove(0).0))
        }
    }

    fn mem_check(&self) -> Option<RTShark> {
        let mut system = System::new();
        let pid = Pid::from_u32(self.current.pid()?);
        system.refresh_process_specifics(pid, ProcessRefreshKind::new());
        let (process) = system.process(pid)?;
        if process.memory() > self.mem_limit {
            Some(self.builder.clone().spawn().expect("unable to create"))
        } else {
            None
        }
    }
}
