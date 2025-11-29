use egui::{Color32, CornerRadius as Rounding, Frame, Margin, ScrollArea, Stroke};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::sync::{Arc, Mutex};
use std::thread;

pub fn start_ui() {
    eframe::run_native(
        "DeepTrace - Network Monitor",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1200.0, 700.0])
                .with_min_inner_size([800.0, 500.0]),
            ..Default::default()
        },
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(MyApp::new()))
        }),
    )
    .unwrap();
}

#[derive(Clone)]
struct PacketInfo {
    id: usize,
    timestamp: String,
    method: String,
    host: String,
    path: String,
    status: String,
    size: String,
    raw_data: String,
}

struct MyApp {
    packets: Arc<Mutex<Vec<PacketInfo>>>,
    selected_packet: Option<usize>,
    detail_tab: DetailTab,
}

#[derive(PartialEq)]
enum DetailTab {
    Headers,
    HexDump,
    Raw,
}

impl MyApp {
    pub fn new() -> Self {
        let packets = Arc::new(Mutex::new(vec![]));
        let packets_thread = packets.clone();

        thread::spawn(move || {
            let mut cap = core::capture::LiveCapture::open_default().unwrap();
            let mut counter = 0;

            loop {
                if let Some(data) = cap.next() {
                    counter += 1;
                    if let Some(parsed) = parse_packet(data.data, counter) {
                        let mut lock = packets_thread.lock().unwrap();
                        lock.push(parsed);
                        if lock.len() > 1000 {
                            lock.remove(0);
                        }
                    }
                }
            }
        });

        Self {
            packets,
            selected_packet: None,
            detail_tab: DetailTab::HexDump,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("🔍 DeepTrace");
                ui.separator();
                ui.label("Network Monitor");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let packet_count = self.packets.lock().unwrap().len();
                    ui.label(format!("📦 {} packets", packet_count));
                });
            });
            ui.add_space(4.0);
        });

        egui::SidePanel::left("requests_list")
            .resizable(true)
            .default_width(500.0)
            .min_width(300.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.heading("Requests");
                ui.separator();

                ui.horizontal(|ui| {
                    ui.style_mut().spacing.item_spacing.x = 10.0;
                    ui.label(egui::RichText::new("ID").strong().color(Color32::GRAY));
                    ui.label(egui::RichText::new("Time").strong().color(Color32::GRAY));
                    ui.label(egui::RichText::new("Method").strong().color(Color32::GRAY));
                    ui.label(egui::RichText::new("Host").strong().color(Color32::GRAY));
                    ui.label(egui::RichText::new("Status").strong().color(Color32::GRAY));
                });
                ui.separator();

                ScrollArea::vertical().show(ui, |ui| {
                    let packets = self.packets.lock().unwrap();

                    for (idx, packet) in packets.iter().enumerate().rev() {
                        let is_selected = self.selected_packet == Some(idx);

                        let response = ui.add(
                            egui::Button::new("")
                                .frame(true)
                                .fill(if is_selected {
                                    Color32::from_rgb(45, 55, 72)
                                } else {
                                    Color32::from_rgb(26, 32, 44)
                                })
                                .stroke(Stroke::new(
                                    1.0,
                                    if is_selected {
                                        Color32::from_rgb(66, 153, 225)
                                    } else {
                                        Color32::from_rgb(45, 55, 72)
                                    },
                                ))
                                .corner_radius(Rounding::same(4))
                                .min_size(egui::vec2(ui.available_width(), 32.0)),
                        );

                        let rect = response.rect;

                        if response.clicked() {
                            self.selected_packet = Some(idx);
                        }

                        ui.allocate_ui_at_rect(rect, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_space(8.0);
                                ui.label(format!("#{}", packet.id));
                                ui.add_space(8.0);
                                ui.label(&packet.timestamp);
                                ui.add_space(8.0);

                                let method_color = match packet.method.as_str() {
                                    "GET" => Color32::from_rgb(72, 187, 120),
                                    "POST" => Color32::from_rgb(66, 153, 225),
                                    "PUT" => Color32::from_rgb(237, 137, 54),
                                    "DELETE" => Color32::from_rgb(245, 101, 101),
                                    _ => Color32::GRAY,
                                };

                                ui.label(
                                    egui::RichText::new(&packet.method)
                                        .color(method_color)
                                        .strong(),
                                );
                                ui.add_space(8.0);
                                ui.label(&packet.host);
                                ui.add_space(8.0);

                                let status_color = if packet.status.starts_with('2') {
                                    Color32::from_rgb(72, 187, 120)
                                } else if packet.status.starts_with('3') {
                                    Color32::from_rgb(237, 137, 54)
                                } else if packet.status.starts_with('4')
                                    || packet.status.starts_with('5')
                                {
                                    Color32::from_rgb(245, 101, 101)
                                } else {
                                    Color32::GRAY
                                };

                                ui.label(egui::RichText::new(&packet.status).color(status_color));
                            });
                        });

                        ui.add_space(2.0);
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(selected_idx) = self.selected_packet {
                let packets = self.packets.lock().unwrap();
                if let Some(packet) = packets.get(selected_idx) {
                    ui.add_space(4.0);

                    Frame::NONE
                        .fill(Color32::from_rgb(26, 32, 44))
                        .corner_radius(Rounding::same(8))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.heading(format!("Request #{}", packet.id));
                                ui.label("|");
                                ui.label(&packet.timestamp);
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(&packet.method).strong().size(16.0));
                                ui.label(
                                    egui::RichText::new(format!("{}{}", packet.host, packet.path))
                                        .size(16.0),
                                );
                            });
                        });

                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::Headers, "Headers")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::Headers;
                        }
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::HexDump, "Hex Dump")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::HexDump;
                        }
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::Raw, "Raw")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::Raw;
                        }
                    });

                    ui.separator();

                    ScrollArea::vertical().show(ui, |ui| match self.detail_tab {
                        DetailTab::Headers => {
                            ui.group(|ui| {
                                ui.label(egui::RichText::new("Request Headers").strong());
                                ui.separator();
                                ui.monospace("Host: ".to_string() + &packet.host);
                                ui.monospace("Method: ".to_string() + &packet.method);
                                ui.monospace("Path: ".to_string() + &packet.path);
                                ui.monospace("Status: ".to_string() + &packet.status);
                                ui.monospace("Size: ".to_string() + &packet.size);
                            });
                        }
                        DetailTab::HexDump => {
                            Frame::NONE
                                .fill(Color32::from_rgb(17, 24, 39))
                                .corner_radius(Rounding::same(4))
                                .inner_margin(Margin::same(8))
                                .show(ui, |ui| {
                                    ui.monospace(&packet.raw_data);
                                });
                        }
                        DetailTab::Raw => {
                            Frame::NONE
                                .fill(Color32::from_rgb(17, 24, 39))
                                .corner_radius(Rounding::same(4))
                                .inner_margin(Margin::same(8))
                                .show(ui, |ui| {
                                    ui.monospace(&packet.raw_data);
                                });
                        }
                    });
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label("Packet not found");
                    });
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new("Select a request to view details")
                            .size(18.0)
                            .color(Color32::GRAY),
                    );
                });
            }
        });

        ctx.request_repaint();
    }
}

fn parse_packet(data: &[u8], counter: usize) -> Option<PacketInfo> {
    let dump = core::hex_dump(data);
    let timestamp = chrono::Local::now().format("%H:%M:%S%.3f").to_string();

    let ethernet = match EthernetPacket::new(data) {
        Some(eth) => eth,
        None => return Some(create_default_packet(counter, timestamp, data, dump)),
    };

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                return parse_ipv4_packet(&ipv4, counter, timestamp, data.len(), dump);
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                return parse_ipv6_packet(&ipv6, counter, timestamp, data.len(), dump);
            }
        }
        EtherTypes::Arp => {
            return Some(PacketInfo {
                id: counter,
                timestamp,
                method: "ARP".to_string(),
                host: "ARP Request/Reply".to_string(),
                path: "-".to_string(),
                status: "-".to_string(),
                size: format!("{} B", data.len()),
                raw_data: dump,
            });
        }
        _ => {}
    }

    Some(create_default_packet(counter, timestamp, data, dump))
}

fn parse_ipv4_packet(
    ipv4: &Ipv4Packet,
    counter: usize,
    timestamp: String,
    total_size: usize,
    dump: String,
) -> Option<PacketInfo> {
    let src_ip = ipv4.get_source();
    let dst_ip = ipv4.get_destination();

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                return parse_tcp_packet(
                    &tcp,
                    src_ip.to_string(),
                    dst_ip.to_string(),
                    counter,
                    timestamp,
                    total_size,
                    dump,
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                return Some(PacketInfo {
                    id: counter,
                    timestamp,
                    method: "UDP".to_string(),
                    host: format!("{}:{}", dst_ip, udp.get_destination()),
                    path: format!("← {}:{}", src_ip, udp.get_source()),
                    status: "-".to_string(),
                    size: format!("{} B", total_size),
                    raw_data: dump,
                });
            }
        }
        IpNextHeaderProtocols::Icmp => {
            return Some(PacketInfo {
                id: counter,
                timestamp,
                method: "ICMP".to_string(),
                host: dst_ip.to_string(),
                path: format!("← {}", src_ip),
                status: "-".to_string(),
                size: format!("{} B", total_size),
                raw_data: dump,
            });
        }
        _ => {}
    }

    Some(PacketInfo {
        id: counter,
        timestamp,
        method: "IPv4".to_string(),
        host: dst_ip.to_string(),
        path: format!("← {}", src_ip),
        status: "-".to_string(),
        size: format!("{} B", total_size),
        raw_data: dump,
    })
}

fn parse_ipv6_packet(
    ipv6: &Ipv6Packet,
    counter: usize,
    timestamp: String,
    total_size: usize,
    dump: String,
) -> Option<PacketInfo> {
    let src_ip = ipv6.get_source();
    let dst_ip = ipv6.get_destination();

    match ipv6.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                return parse_tcp_packet(
                    &tcp,
                    src_ip.to_string(),
                    dst_ip.to_string(),
                    counter,
                    timestamp,
                    total_size,
                    dump,
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                return Some(PacketInfo {
                    id: counter,
                    timestamp,
                    method: "UDP".to_string(),
                    host: format!("[{}]:{}", dst_ip, udp.get_destination()),
                    path: format!("← [{}]:{}", src_ip, udp.get_source()),
                    status: "-".to_string(),
                    size: format!("{} B", total_size),
                    raw_data: dump,
                });
            }
        }
        _ => {}
    }

    Some(PacketInfo {
        id: counter,
        timestamp,
        method: "IPv6".to_string(),
        host: dst_ip.to_string(),
        path: format!("← {}", src_ip),
        status: "-".to_string(),
        size: format!("{} B", total_size),
        raw_data: dump,
    })
}

fn parse_tcp_packet(
    tcp: &TcpPacket,
    src_ip: String,
    dst_ip: String,
    counter: usize,
    timestamp: String,
    total_size: usize,
    dump: String,
) -> Option<PacketInfo> {
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    let payload = tcp.payload();

    if payload.is_empty() {
        let flags = format_tcp_flags(tcp);
        return Some(PacketInfo {
            id: counter,
            timestamp,
            method: "TCP".to_string(),
            host: format!("{}:{}", dst_ip, dst_port),
            path: format!("← {}:{}", src_ip, src_port),
            status: flags,
            size: format!("{} B", total_size),
            raw_data: dump,
        });
    }

    if let Some(http_info) = parse_http_request(payload) {
        return Some(PacketInfo {
            id: counter,
            timestamp,
            method: http_info.method,
            host: http_info.host,
            path: http_info.path,
            status: "→".to_string(),
            size: format!("{} B", total_size),
            raw_data: dump,
        });
    }

    if let Some(http_info) = parse_http_response(payload) {
        return Some(PacketInfo {
            id: counter,
            timestamp,
            method: "RESP".to_string(),
            host: format!("{}:{}", src_ip, src_port),
            path: http_info.reason,
            status: http_info.status_code,
            size: format!("{} B", total_size),
            raw_data: dump,
        });
    }

    let protocol = match dst_port {
        443 => "HTTPS",
        80 => "HTTP",
        22 => "SSH",
        21 => "FTP",
        25 => "SMTP",
        53 => "DNS",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        _ => "TCP",
    };

    Some(PacketInfo {
        id: counter,
        timestamp,
        method: protocol.to_string(),
        host: format!("{}:{}", dst_ip, dst_port),
        path: format!("← {}:{}", src_ip, src_port),
        status: format_tcp_flags(tcp),
        size: format!("{} B (payload: {} B)", total_size, payload.len()),
        raw_data: dump,
    })
}

fn format_tcp_flags(tcp: &TcpPacket) -> String {
    let mut flags = Vec::new();
    if tcp.get_flags() & 0x02 != 0 {
        flags.push("SYN");
    }
    if tcp.get_flags() & 0x10 != 0 {
        flags.push("ACK");
    }
    if tcp.get_flags() & 0x01 != 0 {
        flags.push("FIN");
    }
    if tcp.get_flags() & 0x04 != 0 {
        flags.push("RST");
    }
    if tcp.get_flags() & 0x08 != 0 {
        flags.push("PSH");
    }
    if tcp.get_flags() & 0x20 != 0 {
        flags.push("URG");
    }

    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join("|")
    }
}

fn create_default_packet(
    counter: usize,
    timestamp: String,
    data: &[u8],
    dump: String,
) -> PacketInfo {
    PacketInfo {
        id: counter,
        timestamp,
        method: "RAW".to_string(),
        host: "unknown".to_string(),
        path: "-".to_string(),
        status: "-".to_string(),
        size: format!("{} B", data.len()),
        raw_data: dump,
    }
}

struct HttpRequestInfo {
    method: String,
    host: String,
    path: String,
}

struct HttpResponseInfo {
    status_code: String,
    reason: String,
}

fn parse_http_request(data: &[u8]) -> Option<HttpRequestInfo> {
    if !data.starts_with(b"GET")
        && !data.starts_with(b"POST")
        && !data.starts_with(b"PUT")
        && !data.starts_with(b"DELETE")
        && !data.starts_with(b"HEAD")
        && !data.starts_with(b"OPTIONS")
        && !data.starts_with(b"PATCH")
        && !data.starts_with(b"CONNECT")
    {
        return None;
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(data) {
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {
            let method = req.method?.to_string();
            let path = req.path?.to_string();

            let host = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("Host"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .unwrap_or("unknown")
                .to_string();

            Some(HttpRequestInfo { method, host, path })
        }
        _ => None,
    }
}

fn parse_http_response(data: &[u8]) -> Option<HttpResponseInfo> {
    if !data.starts_with(b"HTTP/") {
        return None;
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);

    match resp.parse(data) {
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {
            let status_code = resp.code?.to_string();
            let reason = resp.reason?.to_string();

            Some(HttpResponseInfo {
                status_code,
                reason,
            })
        }
        _ => None,
    }
}
