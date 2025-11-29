use anyhow::Result;

use pcap::{Capture, Device, Error};

pub struct LiveCapture {
    cap: Capture<pcap::Active>,
}

#[derive(Debug, Clone)]
pub struct NetInterface {
    pub name: String,
    pub desc: Option<String>,
}

impl LiveCapture {
    pub fn open_default() -> Result<Self> {
        let dev = Device::lookup()?.expect("No network devices found");
        let cap = Capture::from_device(dev)?
            .immediate_mode(true)
            .promisc(true)
            .open()?;

        Ok(Self { cap })
    }

    pub fn open(name: &str) -> Result<Self> {
        let dev = Device::list()?
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| Error::InvalidInputString)?;

        let cap = Capture::from_device(dev)?
            .immediate_mode(true)
            .promisc(true)
            .open()?;

        Ok(Self { cap })
    }

    pub fn list_interfaces() -> Result<Vec<NetInterface>> {
        let devs = Device::list()?;
        Ok(devs.into_iter()
            .map(|d| NetInterface {
                name: d.name,
                desc: d.desc,
            })
            .collect())
    }


    pub fn next(&'_ mut self) -> Option<pcap::Packet<'_>> {
        match self.cap.next_packet() {
            Ok(pkt) => Some(pkt),
            Err(_) => None,
        }
    }
}
