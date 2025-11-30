extern crate pnet;

use egui::{Color32, CornerRadius as Rounding, Frame, Margin, ScrollArea, Stroke, Vec2};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

pub fn start_ui() {
    eframe::run_native(
        "DeepTrace - Advanced Network Monitor",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1400.0, 800.0])
                .with_min_inner_size([1000.0, 600.0]),
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
    instant: Instant,
    method: String,
    host: String,
    path: String,
    status: String,
    size: usize,
    raw_data: String,
    protocol: String,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    flags: String,
    payload_size: usize,
}

#[derive(Clone)]
struct Statistics {
    total_packets: usize,
    total_bytes: usize,
    packets_per_protocol: HashMap<String, usize>,
    bytes_per_protocol: HashMap<String, usize>,
    packets_per_second: f64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            packets_per_protocol: HashMap::new(),
            bytes_per_protocol: HashMap::new(),
            packets_per_second: 0.0,
            start_time: Instant::now(),
        }
    }

    fn update(&mut self, packet: &PacketInfo) {
        self.total_packets += 1;
        self.total_bytes += packet.size;

        *self
            .packets_per_protocol
            .entry(packet.protocol.clone())
            .or_insert(0) += 1;
        *self
            .bytes_per_protocol
            .entry(packet.protocol.clone())
            .or_insert(0) += packet.size;

        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.packets_per_second = self.total_packets as f64 / elapsed;
        }
    }
}

struct FilterConfig {
    enabled: bool,
    protocol_filter: String,
    host_filter: String,
    port_filter: String,
    method_filter: String,
    min_size: String,
    max_size: String,
    show_tcp: bool,
    show_udp: bool,
    show_http: bool,
    show_https: bool,
    show_dns: bool,
    show_other: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol_filter: String::new(),
            host_filter: String::new(),
            port_filter: String::new(),
            method_filter: String::new(),
            min_size: String::new(),
            max_size: String::new(),
            show_tcp: true,
            show_udp: true,
            show_http: true,
            show_https: true,
            show_dns: true,
            show_other: true,
        }
    }
}

impl FilterConfig {
    fn matches(&self, packet: &PacketInfo) -> bool {
        if !self.enabled {
            return true;
        }

        // Protocol type filters
        let protocol_match = match packet.protocol.as_str() {
            "TCP" => self.show_tcp,
            "UDP" => self.show_udp,
            "HTTP" | "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => {
                self.show_http
            }
            "HTTPS" => self.show_https,
            "DNS" => self.show_dns,
            _ => self.show_other,
        };

        if !protocol_match {
            return false;
        }

        // Text filters
        if !self.protocol_filter.is_empty()
            && !packet
                .protocol
                .to_lowercase()
                .contains(&self.protocol_filter.to_lowercase())
        {
            return false;
        }

        if !self.host_filter.is_empty()
            && !packet
                .host
                .to_lowercase()
                .contains(&self.host_filter.to_lowercase())
            && !packet.src_ip.contains(&self.host_filter)
            && !packet.dst_ip.contains(&self.host_filter)
        {
            return false;
        }

        if !self.port_filter.is_empty() {
            if let Ok(port) = self.port_filter.parse::<u16>() {
                if packet.src_port != port && packet.dst_port != port {
                    return false;
                }
            }
        }

        if !self.method_filter.is_empty()
            && !packet
                .method
                .to_lowercase()
                .contains(&self.method_filter.to_lowercase())
        {
            return false;
        }

        // Size filters
        if !self.min_size.is_empty() {
            if let Ok(min) = self.min_size.parse::<usize>() {
                if packet.size < min {
                    return false;
                }
            }
        }

        if !self.max_size.is_empty() {
            if let Ok(max) = self.max_size.parse::<usize>() {
                if packet.size > max {
                    return false;
                }
            }
        }

        true
    }
}

struct MyApp {
    packets: Arc<Mutex<Vec<PacketInfo>>>,
    statistics: Arc<Mutex<Statistics>>,
    selected_packet: Option<usize>,
    detail_tab: DetailTab,
    filter_config: FilterConfig,
    show_filters: bool,
    show_statistics: bool,
    paused: bool,
    search_query: String,
    auto_scroll: bool,
}

#[derive(PartialEq)]
enum DetailTab {
    Overview,
    Headers,
    HexDump,
    Payload,
    Auto,
}

impl MyApp {
    pub fn new() -> Self {
        let packets = Arc::new(Mutex::new(vec![]));
        let statistics = Arc::new(Mutex::new(Statistics::new()));
        let packets_thread = packets.clone();
        let stats_thread = statistics.clone();

        thread::spawn(move || {
            let mut cap = core::capture::LiveCapture::open_default()
                .map_err(|e| {
                    panic!("Error opening capture, run as sudo ?: {}", e);
                })
                .unwrap();
            let mut counter = 0;

            loop {
                if let Some(data) = cap.next() {
                    counter += 1;
                    if let Some(parsed) = parse_packet(data.data, counter) {
                        {
                            let mut stats = stats_thread.lock().unwrap();
                            stats.update(&parsed);
                        }

                        let mut lock = packets_thread.lock().unwrap();
                        lock.push(parsed);
                        if lock.len() > 5000 {
                            lock.remove(0);
                        }
                    }
                }
            }
        });

        Self {
            packets,
            statistics,
            selected_packet: None,
            detail_tab: DetailTab::Overview,
            filter_config: FilterConfig::default(),
            show_filters: false,
            show_statistics: true,
            paused: false,
            search_query: String::new(),
            auto_scroll: true,
        }
    }

    fn get_filtered_packets(&self) -> Vec<(usize, PacketInfo)> {
        let packets = self.packets.lock().unwrap();
        packets
            .iter()
            .enumerate()
            .filter(|(_, p)| self.filter_config.matches(p))
            .filter(|(_, p)| {
                if self.search_query.is_empty() {
                    return true;
                }
                let query = self.search_query.to_lowercase();
                p.host.to_lowercase().contains(&query)
                    || p.method.to_lowercase().contains(&query)
                    || p.path.to_lowercase().contains(&query)
                    || p.src_ip.contains(&query)
                    || p.dst_ip.contains(&query)
                    || p.protocol.to_lowercase().contains(&query)
            })
            .map(|(idx, p)| (idx, p.clone()))
            .collect()
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top bar
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("🔍 DeepTrace Pro");
                ui.separator();

                let stats = self.statistics.lock().unwrap();
                ui.label(format!("📦 {} packets", stats.total_packets));
                ui.separator();
                ui.label(format!("📊 {:.1} pkt/s", stats.packets_per_second));
                ui.separator();
                ui.label(format!("💾 {}", format_bytes(stats.total_bytes)));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(if self.paused {
                            "▶ Resume"
                        } else {
                            "⏸ Pause"
                        })
                        .clicked()
                    {
                        self.paused = !self.paused;
                    }

                    if ui.button("🗑 Clear").clicked() {
                        self.packets.lock().unwrap().clear();
                        self.selected_packet = None;
                        *self.statistics.lock().unwrap() = Statistics::new();
                    }

                    ui.checkbox(&mut self.show_statistics, "📈 Stats");
                    ui.checkbox(&mut self.show_filters, "🔧 Filters");
                });
            });
            ui.add_space(6.0);
        });

        // Statistics panel
        if self.show_statistics {
            egui::TopBottomPanel::top("statistics_panel")
                .resizable(false)
                .show(ctx, |ui| {
                    Frame::NONE
                        .fill(Color32::from_rgb(26, 32, 44))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let stats = self.statistics.lock().unwrap();

                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new("Protocol Distribution").strong());
                                    ui.add_space(4.0);
                                    let mut protocols: Vec<_> =
                                        stats.packets_per_protocol.iter().collect();
                                    protocols.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

                                    for (proto, count) in protocols.iter().take(5) {
                                        let percentage =
                                            (**count as f64 / stats.total_packets as f64) * 100.0;
                                        ui.horizontal(|ui| {
                                            ui.label(format!("{}: ", proto));
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{} ({:.1}%)",
                                                    count, percentage
                                                ))
                                                .color(Color32::from_rgb(66, 153, 225)),
                                            );
                                        });
                                    }
                                });

                                ui.separator();

                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new("Top Bandwidth").strong());
                                    ui.add_space(4.0);
                                    let mut bandwidth: Vec<_> =
                                        stats.bytes_per_protocol.iter().collect();
                                    bandwidth.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));

                                    for (proto, bytes) in bandwidth.iter().take(5) {
                                        ui.horizontal(|ui| {
                                            ui.label(format!("{}: ", proto));
                                            ui.label(
                                                egui::RichText::new(format_bytes(**bytes))
                                                    .color(Color32::from_rgb(72, 187, 120)),
                                            );
                                        });
                                    }
                                });

                                ui.separator();

                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new("Network Info").strong());
                                    ui.add_space(4.0);
                                    let elapsed = stats.start_time.elapsed();
                                    ui.label(format!("Uptime: {}s", elapsed.as_secs()));
                                    ui.label(format!(
                                        "Avg packet size: {}",
                                        format_bytes(if stats.total_packets > 0 {
                                            stats.total_bytes / stats.total_packets
                                        } else {
                                            0
                                        })
                                    ));
                                    ui.label(format!(
                                        "Bandwidth: {}/s",
                                        format_bytes(
                                            (stats.total_bytes as f64 / elapsed.as_secs_f64())
                                                as usize
                                        )
                                    ));
                                });
                            });
                        });
                });
        }

        // Filters panel
        if self.show_filters {
            egui::TopBottomPanel::top("filters_panel")
                .resizable(false)
                .show(ctx, |ui| {
                    Frame::NONE
                        .fill(Color32::from_rgb(26, 32, 44))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.filter_config.enabled, "Enable Filters");
                                ui.separator();

                                ui.label("Quick Filters:");
                                ui.checkbox(&mut self.filter_config.show_http, "HTTP");
                                ui.checkbox(&mut self.filter_config.show_https, "HTTPS");
                                ui.checkbox(&mut self.filter_config.show_tcp, "TCP");
                                ui.checkbox(&mut self.filter_config.show_udp, "UDP");
                                ui.checkbox(&mut self.filter_config.show_dns, "DNS");
                                ui.checkbox(&mut self.filter_config.show_other, "Other");
                            });

                            ui.add_space(8.0);

                            ui.horizontal(|ui| {
                                ui.label("Host/IP:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.filter_config.host_filter)
                                        .desired_width(150.0)
                                        .hint_text("e.g., google.com"),
                                );

                                ui.separator();

                                ui.label("Port:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.filter_config.port_filter)
                                        .desired_width(80.0)
                                        .hint_text("e.g., 443"),
                                );

                                ui.separator();

                                ui.label("Method:");
                                ui.add(
                                    egui::TextEdit::singleline(
                                        &mut self.filter_config.method_filter,
                                    )
                                    .desired_width(100.0)
                                    .hint_text("e.g., GET"),
                                );

                                ui.separator();

                                ui.label("Size:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.filter_config.min_size)
                                        .desired_width(70.0)
                                        .hint_text("min"),
                                );
                                ui.label("-");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.filter_config.max_size)
                                        .desired_width(70.0)
                                        .hint_text("max"),
                                );

                                if ui.button("🗑 Clear Filters").clicked() {
                                    self.filter_config = FilterConfig::default();
                                }
                            });
                        });
                });
        }

        // Search bar
        egui::TopBottomPanel::top("search_panel")
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("🔍 Search:");
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.search_query)
                            .desired_width(300.0)
                            .hint_text("Search in host, method, path, IP..."),
                    );

                    if !self.search_query.is_empty() && ui.button("✖").clicked() {
                        self.search_query.clear();
                    }

                    ui.separator();
                    ui.checkbox(&mut self.auto_scroll, "Auto-scroll");
                });
                ui.add_space(4.0);
            });

        // Left panel - packet list
        egui::SidePanel::left("requests_list")
            .resizable(true)
            .default_width(600.0)
            .min_width(400.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);

                let filtered = self.get_filtered_packets();
                ui.horizontal(|ui| {
                    ui.heading("Packets");
                    ui.label(format!("({} displayed)", filtered.len()));
                });
                ui.separator();

                // Column headers
                ui.horizontal(|ui| {
                    ui.style_mut().spacing.item_spacing.x = 8.0;
                    ui.label(egui::RichText::new("ID").strong().color(Color32::GRAY));
                    ui.label(egui::RichText::new("Time").strong().color(Color32::GRAY));
                    ui.label(
                        egui::RichText::new("Protocol")
                            .strong()
                            .color(Color32::GRAY),
                    );
                    ui.label(
                        egui::RichText::new("Source → Destination")
                            .strong()
                            .color(Color32::GRAY),
                    );
                    ui.label(egui::RichText::new("Info").strong().color(Color32::GRAY));
                    ui.label(egui::RichText::new("Size").strong().color(Color32::GRAY));
                });
                ui.separator();

                let mut scroll_area = ScrollArea::vertical();
                if self.auto_scroll {
                    scroll_area = scroll_area.stick_to_bottom(true);
                }

                scroll_area.show(ui, |ui| {
                    for (original_idx, packet) in filtered.iter().rev() {
                        let is_selected = self.selected_packet == Some(*original_idx);

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
                                .min_size(Vec2::new(ui.available_width(), 40.0)),
                        );

                        let rect = response.rect;

                        if response.clicked() {
                            self.selected_packet = Some(*original_idx);
                            self.auto_scroll = false;
                        }

                        ui.allocate_ui_at_rect(rect, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_space(8.0);

                                // ID
                                ui.label(
                                    egui::RichText::new(format!("#{}", packet.id))
                                        .color(Color32::LIGHT_GRAY),
                                );
                                ui.add_space(8.0);

                                // Time
                                ui.label(&packet.timestamp);
                                ui.add_space(8.0);

                                // Protocol with color
                                let protocol_color = get_protocol_color(&packet.protocol);
                                ui.label(
                                    egui::RichText::new(&packet.protocol)
                                        .color(protocol_color)
                                        .strong(),
                                );
                                ui.add_space(8.0);

                                // Connection info
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}:{} → {}:{}",
                                        truncate_ip(&packet.src_ip),
                                        packet.src_port,
                                        truncate_ip(&packet.dst_ip),
                                        packet.dst_port
                                    ))
                                    .color(Color32::LIGHT_BLUE),
                                );
                                ui.add_space(8.0);

                                // Additional info
                                if !packet.path.is_empty() && packet.path != "-" {
                                    ui.label(truncate_string(&packet.path, 30));
                                } else if !packet.flags.is_empty() && packet.flags != "-" {
                                    ui.label(
                                        egui::RichText::new(&packet.flags).color(Color32::YELLOW),
                                    );
                                }
                                ui.add_space(8.0);

                                // Size
                                ui.label(format_bytes(packet.size));
                            });
                        });

                        ui.add_space(2.0);
                    }
                });
            });

        // Central panel - packet details
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(selected_idx) = self.selected_packet {
                let packets = self.packets.lock().unwrap();
                if let Some(packet) = packets.get(selected_idx) {
                    ui.add_space(4.0);

                    // Header info
                    Frame::NONE
                        .fill(Color32::from_rgb(26, 32, 44))
                        .corner_radius(Rounding::same(8))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.heading(format!("Packet #{}", packet.id));
                                ui.label("|");
                                ui.label(&packet.timestamp);
                                ui.label("|");
                                ui.label(
                                    egui::RichText::new(&packet.protocol)
                                        .color(get_protocol_color(&packet.protocol))
                                        .strong(),
                                );
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}:{} → {}:{}",
                                        packet.src_ip,
                                        packet.src_port,
                                        packet.dst_ip,
                                        packet.dst_port
                                    ))
                                    .size(14.0),
                                );
                            });
                        });

                    ui.add_space(8.0);

                    // Tabs
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::Overview, "📋 Overview")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::Overview;
                        }
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::Headers, "📝 Headers")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::Headers;
                        }
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::HexDump, "🔢 Hex Dump")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::HexDump;
                        }
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::Payload, "📦 Payload")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::Payload;
                        }
                        if ui
                            .selectable_label(self.detail_tab == DetailTab::Auto, "📦 AUTO")
                            .clicked()
                        {
                            self.detail_tab = DetailTab::Auto;
                        }
                    });

                    ui.separator();

                    ScrollArea::vertical().show(ui, |ui| match self.detail_tab {
                        DetailTab::Overview => {
                            ui.group(|ui| {
                                ui.label(
                                    egui::RichText::new("General Information")
                                        .strong()
                                        .size(16.0),
                                );
                                ui.separator();

                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Protocol:").strong());
                                    ui.label(&packet.protocol);
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Method/Type:").strong());
                                    ui.label(&packet.method);
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Total Size:").strong());
                                    ui.label(format_bytes(packet.size));
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Payload Size:").strong());
                                    ui.label(format_bytes(packet.payload_size));
                                });
                            });

                            ui.add_space(8.0);

                            ui.group(|ui| {
                                ui.label(
                                    egui::RichText::new("Network Information")
                                        .strong()
                                        .size(16.0),
                                );
                                ui.separator();

                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Source IP:").strong());
                                    ui.label(&packet.src_ip);
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Source Port:").strong());
                                    ui.label(packet.src_port.to_string());
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Destination IP:").strong());
                                    ui.label(&packet.dst_ip);
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Destination Port:").strong());
                                    ui.label(packet.dst_port.to_string());
                                });
                                if !packet.flags.is_empty() && packet.flags != "-" {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("TCP Flags:").strong());
                                        ui.label(
                                            egui::RichText::new(&packet.flags)
                                                .color(Color32::YELLOW),
                                        );
                                    });
                                }
                            });

                            if !packet.host.is_empty()
                                && packet.host != "unknown"
                                && packet.host != "-"
                            {
                                ui.add_space(8.0);
                                ui.group(|ui| {
                                    ui.label(
                                        egui::RichText::new("Application Information")
                                            .strong()
                                            .size(16.0),
                                    );
                                    ui.separator();

                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("Host:").strong());
                                        ui.label(&packet.host);
                                    });
                                    if !packet.path.is_empty() && packet.path != "-" {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("Path:").strong());
                                            ui.label(&packet.path);
                                        });
                                    }
                                    if !packet.status.is_empty() && packet.status != "-" {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("Status:").strong());
                                            ui.label(&packet.status);
                                        });
                                    }
                                });
                            }
                        }
                        DetailTab::Headers => {
                            ui.group(|ui| {
                                ui.label(egui::RichText::new("Packet Headers").strong());
                                ui.separator();
                                ui.monospace(format!("ID: {}", packet.id));
                                ui.monospace(format!("Timestamp: {}", packet.timestamp));
                                ui.monospace(format!("Protocol: {}", packet.protocol));
                                ui.monospace(format!("Method: {}", packet.method));
                                ui.monospace(format!(
                                    "Source: {}:{}",
                                    packet.src_ip, packet.src_port
                                ));
                                ui.monospace(format!(
                                    "Destination: {}:{}",
                                    packet.dst_ip, packet.dst_port
                                ));
                                ui.monospace(format!("Host: {}", packet.host));
                                ui.monospace(format!("Path: {}", packet.path));
                                ui.monospace(format!("Status: {}", packet.status));
                                ui.monospace(format!("Flags: {}", packet.flags));
                                ui.monospace(format!("Total Size: {} bytes", packet.size));
                                ui.monospace(format!(
                                    "Payload Size: {} bytes",
                                    packet.payload_size
                                ));
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
                        DetailTab::Payload => {
                            Frame::NONE
                                .fill(Color32::from_rgb(17, 24, 39))
                                .corner_radius(Rounding::same(4))
                                .inner_margin(Margin::same(8))
                                .show(ui, |ui| {
                                    if packet.payload_size > 0 {
                                        ui.monospace(format!(
                                            "Payload Size: {} bytes\n\n",
                                            packet.payload_size
                                        ));
                                        ui.monospace(&packet.raw_data);
                                    } else {
                                        ui.monospace("No payload data available");
                                    }
                                });
                        }
                        DetailTab::Auto => {
                            Frame::NONE
                                .fill(Color32::from_rgb(17, 24, 39))
                                .corner_radius(Rounding::same(4))
                                .inner_margin(Margin::same(8))
                                .show(ui, |ui| {
                                    ui.monospace(
                                        &proto::msgpack_decoder::auto_parse(
                                            packet.raw_data.as_ref(),
                                        )
                                        .unwrap()
                                        .to_string(),
                                    );
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
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("Select a packet to view details")
                                .size(20.0)
                                .color(Color32::GRAY),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("Use filters and search to find specific packets")
                                .size(14.0)
                                .color(Color32::DARK_GRAY),
                        );
                    });
                });
            }
        });

        if !self.paused {
            ctx.request_repaint();
        }
    }
}

fn parse_packet(data: &[u8], counter: usize) -> Option<PacketInfo> {
    let dump = create_enhanced_hex_dump(data);
    let timestamp = chrono::Local::now().format("%H:%M:%S%.3f").to_string();
    let instant = Instant::now();

    let ethernet = match EthernetPacket::new(data) {
        Some(eth) => eth,
        None => {
            return Some(create_default_packet(
                counter, timestamp, instant, data, dump,
            ))
        }
    };

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                return parse_ipv4_packet(&ipv4, counter, timestamp, instant, data.len(), dump);
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                return parse_ipv6_packet(&ipv6, counter, timestamp, instant, data.len(), dump);
            }
        }
        EtherTypes::Arp => {
            return Some(PacketInfo {
                id: counter,
                timestamp,
                instant,
                method: "REQUEST".to_string(),
                host: "ARP".to_string(),
                path: "-".to_string(),
                status: "-".to_string(),
                size: data.len(),
                raw_data: dump,
                protocol: "ARP".to_string(),
                src_ip: "N/A".to_string(),
                dst_ip: "N/A".to_string(),
                src_port: 0,
                dst_port: 0,
                flags: "-".to_string(),
                payload_size: 0,
            });
        }
        EtherTypes::WakeOnLan => {
            return Some(PacketInfo {
                id: counter,
                timestamp,
                instant,
                method: "MAGIC".to_string(),
                host: "WakeOnLan".to_string(),
                path: "-".to_string(),
                status: "-".to_string(),
                size: data.len(),
                raw_data: dump,
                protocol: "WOL".to_string(),
                src_ip: "N/A".to_string(),
                dst_ip: "N/A".to_string(),
                src_port: 0,
                dst_port: 0,
                flags: "-".to_string(),
                payload_size: 0,
            })
        }
        _ => {}
    }

    Some(create_default_packet(
        counter, timestamp, instant, data, dump,
    ))
}

fn parse_ipv4_packet(
    ipv4: &Ipv4Packet,
    counter: usize,
    timestamp: String,
    instant: Instant,
    total_size: usize,
    dump: String,
) -> Option<PacketInfo> {
    let src_ip = ipv4.get_source().to_string();
    let dst_ip = ipv4.get_destination().to_string();

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                return parse_tcp_packet(
                    &tcp, src_ip, dst_ip, counter, timestamp, instant, total_size, dump,
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                let payload = udp.payload();

                // DNS detection
                let protocol = if src_port == 53 || dst_port == 53 {
                    "DNS"
                } else {
                    "UDP"
                };

                return Some(PacketInfo {
                    id: counter,
                    timestamp,
                    instant,
                    method: protocol.to_string(),
                    host: dst_ip.clone(),
                    path: format!("from {}", src_ip),
                    status: "-".to_string(),
                    size: total_size,
                    raw_data: dump,
                    protocol: protocol.to_string(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    flags: "-".to_string(),
                    payload_size: payload.len(),
                });
            }
        }
        IpNextHeaderProtocols::Icmp => {
            return Some(PacketInfo {
                id: counter,
                timestamp,
                instant,
                method: "PING".to_string(),
                host: dst_ip.clone(),
                path: format!("from {}", src_ip),
                status: "-".to_string(),
                size: total_size,
                raw_data: dump,
                protocol: "ICMP".to_string(),
                src_ip,
                dst_ip,
                src_port: 0,
                dst_port: 0,
                flags: "-".to_string(),
                payload_size: 0,
            });
        }
        _ => {}
    }

    Some(PacketInfo {
        id: counter,
        timestamp,
        instant,
        method: "IPv4".to_string(),
        host: dst_ip.clone(),
        path: format!("from {}", src_ip),
        status: "-".to_string(),
        size: total_size,
        raw_data: dump,
        protocol: "IPv4".to_string(),
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port: 0,
        flags: "-".to_string(),
        payload_size: 0,
    })
}

fn parse_ipv6_packet(
    ipv6: &Ipv6Packet,
    counter: usize,
    timestamp: String,
    instant: Instant,
    total_size: usize,
    dump: String,
) -> Option<PacketInfo> {
    let src_ip = ipv6.get_source().to_string();
    let dst_ip = ipv6.get_destination().to_string();

    match ipv6.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                return parse_tcp_packet(
                    &tcp, src_ip, dst_ip, counter, timestamp, instant, total_size, dump,
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                let payload = udp.payload();

                let protocol = if src_port == 53 || dst_port == 53 {
                    "DNS"
                } else {
                    "UDP"
                };

                return Some(PacketInfo {
                    id: counter,
                    timestamp,
                    instant,
                    method: protocol.to_string(),
                    host: dst_ip.clone(),
                    path: format!("from {}", src_ip),
                    status: "-".to_string(),
                    size: total_size,
                    raw_data: dump,
                    protocol: protocol.to_string(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    flags: "-".to_string(),
                    payload_size: payload.len(),
                });
            }
        }
        _ => {}
    }

    Some(PacketInfo {
        id: counter,
        timestamp,
        instant,
        method: "IPv6".to_string(),
        host: dst_ip.clone(),
        path: format!("from {}", src_ip),
        status: "-".to_string(),
        size: total_size,
        raw_data: dump,
        protocol: "IPv6".to_string(),
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port: 0,
        flags: "-".to_string(),
        payload_size: 0,
    })
}

fn parse_tcp_packet(
    tcp: &TcpPacket,
    src_ip: String,
    dst_ip: String,
    counter: usize,
    timestamp: String,
    instant: Instant,
    total_size: usize,
    dump: String,
) -> Option<PacketInfo> {
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    let payload = tcp.payload();
    let flags = format_tcp_flags(tcp);

    if payload.is_empty() {
        return Some(PacketInfo {
            id: counter,
            timestamp,
            instant,
            method: flags.clone(),
            host: dst_ip.clone(),
            path: format!("from {}", src_ip),
            status: "-".to_string(),
            size: total_size,
            raw_data: dump,
            protocol: "TCP".to_string(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flags,
            payload_size: 0,
        });
    }

    // Try parsing HTTP request
    if let Some(http_info) = parse_http_request(payload) {
        return Some(PacketInfo {
            id: counter,
            timestamp,
            instant,
            method: http_info.method.clone(),
            host: http_info.host,
            path: http_info.path,
            status: "→".to_string(),
            size: total_size,
            raw_data: dump,
            protocol: http_info.method,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flags,
            payload_size: payload.len(),
        });
    }

    // Try parsing HTTP response
    if let Some(http_info) = parse_http_response(payload) {
        return Some(PacketInfo {
            id: counter,
            timestamp,
            instant,
            method: "HTTP".to_string(),
            host: format!("{}:{}", src_ip, src_port),
            path: http_info.reason,
            status: http_info.status_code,
            size: total_size,
            raw_data: dump,
            protocol: "HTTP".to_string(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flags,
            payload_size: payload.len(),
        });
    }

    // Protocol detection based on port
    let protocol = match dst_port {
        443 => "HTTPS",
        80 => "HTTP",
        22 => "SSH",
        21 => "FTP",
        25 => "SMTP",
        53 => "DNS",
        110 => "POP3",
        143 => "IMAP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        3389 => "RDP",
        5900 => "VNC",
        8080 => "HTTP-ALT",
        _ => "TCP",
    };

    Some(PacketInfo {
        id: counter,
        timestamp,
        instant,
        method: flags.clone(),
        host: dst_ip.clone(),
        path: format!("from {}", src_ip),
        status: "-".to_string(),
        size: total_size,
        raw_data: dump,
        protocol: protocol.to_string(),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        flags,
        payload_size: payload.len(),
    })
}

fn format_tcp_flags(tcp: &TcpPacket) -> String {
    let mut flags = Vec::new();
    let flag_bits = tcp.get_flags();

    if flag_bits & 0x02 != 0 {
        flags.push("SYN");
    }
    if flag_bits & 0x10 != 0 {
        flags.push("ACK");
    }
    if flag_bits & 0x01 != 0 {
        flags.push("FIN");
    }
    if flag_bits & 0x04 != 0 {
        flags.push("RST");
    }
    if flag_bits & 0x08 != 0 {
        flags.push("PSH");
    }
    if flag_bits & 0x20 != 0 {
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
    instant: Instant,
    data: &[u8],
    dump: String,
) -> PacketInfo {
    PacketInfo {
        id: counter,
        timestamp,
        instant,
        method: "UNKNOWN".to_string(),
        host: "N/A".to_string(),
        path: "-".to_string(),
        status: "-".to_string(),
        size: data.len(),
        raw_data: dump,
        protocol: "RAW".to_string(),
        src_ip: "N/A".to_string(),
        dst_ip: "N/A".to_string(),
        src_port: 0,
        dst_port: 0,
        flags: "-".to_string(),
        payload_size: 0,
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
    let methods = Vec::from([
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    ]);

    if !methods.iter().any(|m| data.starts_with(m.as_ref())) {
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

// Enhanced hex dump with ASCII representation
fn create_enhanced_hex_dump(data: &[u8]) -> String {
    let mut result = String::new();
    let chunk_size = 16;

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        // Offset
        result.push_str(&format!("{:08x}  ", i * chunk_size));

        // Hex values
        for (j, byte) in chunk.iter().enumerate() {
            result.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                result.push(' ');
            }
        }

        // Padding
        let padding = chunk_size - chunk.len();
        for j in 0..padding {
            result.push_str("   ");
            if chunk.len() + j == 8 {
                result.push(' ');
            }
        }

        // ASCII representation
        result.push_str(" |");
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            result.push(ch);
        }
        result.push_str("|\n");

        // Limit dump size for performance
        if i > 100 {
            result.push_str(&format!(
                "... ({} more bytes)\n",
                data.len() - (i * chunk_size)
            ));
            break;
        }
    }

    result
}

fn format_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn get_protocol_color(protocol: &str) -> Color32 {
    match protocol {
        "HTTP" | "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => {
            Color32::from_rgb(72, 187, 120)
        }
        "HTTPS" => Color32::from_rgb(66, 153, 225),
        "TCP" => Color32::from_rgb(159, 122, 234),
        "UDP" => Color32::from_rgb(237, 137, 54),
        "DNS" => Color32::from_rgb(246, 173, 85),
        "ICMP" => Color32::from_rgb(99, 179, 237),
        "ARP" => Color32::from_rgb(144, 205, 244),
        "SSH" | "FTP" | "SMTP" => Color32::from_rgb(229, 62, 62),
        _ => Color32::GRAY,
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn truncate_ip(ip: &str) -> String {
    if ip.len() > 15 {
        truncate_string(ip, 15)
    } else {
        ip.to_string()
    }
}
