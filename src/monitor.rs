use procfs::net::{TcpNetEntry, UdpNetEntry};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, IpAddr};
use std::time::{Instant, Duration};
use sysinfo::{System, Networks, Pid};
use std::fs;

/// tcpdump-style filter for network connections
#[derive(Clone, Debug, Default)]
pub struct ConnectionFilter {
    pub host: Option<String>,           // Filter by IP address (src or dst)
    pub src_host: Option<String>,       // Filter by source IP
    pub dst_host: Option<String>,       // Filter by destination IP
    pub port: Option<u16>,              // Filter by port (src or dst)
    pub src_port: Option<u16>,          // Filter by source port
    pub dst_port: Option<u16>,          // Filter by destination port
    pub protocol: Option<String>,       // Filter by protocol (TCP, UDP, TCP6, UDP6)
    pub process_name: Option<String>,   // Filter by process name
    pub filter_localhost: bool,         // Hide localhost connections
    pub show_closed: bool,              // Show closed connections (TimeWait, CloseWait, etc.)
}

impl ConnectionFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn matches(&self, conn: &ConnectionInfo) -> bool {
        // Filter by localhost
        if self.filter_localhost && conn.is_localhost {
            return false;
        }

        // Filter closed connections (default: hide them)
        if !self.show_closed {
            let state_lower = conn.state.to_lowercase();
            if state_lower.contains("timewait")
                || state_lower.contains("closewait")
                || state_lower.contains("finwait")
                || state_lower.contains("closing")
                || state_lower.contains("lastack")
                || state_lower.contains("closed")
            {
                return false;
            }
        }

        // Filter by host (either src or dst)
        if let Some(ref host) = self.host {
            let local_ip = conn.local_addr.ip().to_string();
            let remote_ip = conn.remote_addr.ip().to_string();
            if !local_ip.contains(host) && !remote_ip.contains(host) {
                return false;
            }
        }

        // Filter by source host
        if let Some(ref src) = self.src_host {
            let local_ip = conn.local_addr.ip().to_string();
            if !local_ip.contains(src) {
                return false;
            }
        }

        // Filter by destination host
        if let Some(ref dst) = self.dst_host {
            let remote_ip = conn.remote_addr.ip().to_string();
            if !remote_ip.contains(dst) {
                return false;
            }
        }

        // Filter by port (either src or dst)
        if let Some(port) = self.port {
            if conn.local_addr.port() != port && conn.remote_addr.port() != port {
                return false;
            }
        }

        // Filter by source port
        if let Some(src_port) = self.src_port {
            if conn.local_addr.port() != src_port {
                return false;
            }
        }

        // Filter by destination port
        if let Some(dst_port) = self.dst_port {
            if conn.remote_addr.port() != dst_port {
                return false;
            }
        }

        // Filter by protocol
        if let Some(ref proto) = self.protocol {
            let proto_upper = proto.to_uppercase();
            if !conn.protocol.contains(&proto_upper) {
                return false;
            }
        }

        // Filter by process name
        if let Some(ref name) = self.process_name {
            let name_lower = name.to_lowercase();
            if !conn.process_name.to_lowercase().contains(&name_lower)
                && !conn.command_path.to_lowercase().contains(&name_lower) {
                return false;
            }
        }

        true
    }
}

/// Statistics for network monitoring (tcpdump-style)
#[derive(Clone, Debug, Default)]
pub struct NetworkStats {
    pub total_connections: usize,
    pub tcp_connections: usize,
    pub udp_connections: usize,
    pub total_upload_speed: u64,    // Total bytes/sec upload
    pub total_download_speed: u64,  // Total bytes/sec download
    pub unique_processes: usize,
}

/// Wireshark-style protocol detection based on port numbers
fn detect_protocol(port: u16, base_proto: &str) -> String {
    let app_proto = match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        465 => "SMTPS",
        587 => "SMTP",
        993 => "IMAPS",
        995 => "POP3S",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        5900..=5999 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        9000..=9999 => "Dev",
        27017 => "MongoDB",
        _ => return base_proto.to_string(),
    };

    format!("{}/{}", base_proto, app_proto)
}

fn simplify_address(addr: &SocketAddr) -> String {
    let ip_str = match addr.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => "localhost".to_string(),
        IpAddr::V6(ip) if ip.is_loopback() => "localhost".to_string(),
        IpAddr::V4(ip) if ip.is_unspecified() => "*".to_string(),
        IpAddr::V6(ip) if ip.is_unspecified() => "*".to_string(),
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => {
            // Simplify common IPv6 addresses
            let s = ip.to_string();
            if s.ends_with(".local") {
                "mDNS".to_string()
            } else {
                s
            }
        }
    };

    if addr.port() == 0 {
        ip_str
    } else {
        format!("{}:{}", ip_str, addr.port())
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ConnectionInfo {
    pub pid: Option<u32>,
    pub process_name: String,
    pub command_path: String,
    pub protocol: String, // "TCP", "UDP", "TCP6", etc.
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub local_addr_display: String,
    pub remote_addr_display: String,
    pub state: String,
    pub inode: u64,
    pub upload_speed: u64, // B/s
    pub download_speed: u64, // B/s
    pub is_localhost: bool,
}

#[allow(dead_code)]
pub struct NetworkMonitor {
    sys: System,
    networks: Networks,
    // Cache Inode -> PID
    inode_cache: HashMap<u64, u32>,
    // Cache PID -> Process Name
    process_name_cache: HashMap<u32, String>,
    last_inode_refresh: Instant,
    last_traffic_update: Instant,
    // Store previous INTERFACE traffic values: (Total Rx, Total Tx, Timestamp)
    interface_traffic_history: (u64, u64, Instant),
    // Total interface speeds: (Download B/s, Upload B/s)
    total_interface_speed: (u64, u64),
    // Debug mode
    debug: bool,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self::new_with_debug(false)
    }

    pub fn new_with_debug(debug: bool) -> Self {
        let now = Instant::now();
        NetworkMonitor {
            sys: System::new_all(),
            networks: Networks::new_with_refreshed_list(),
            inode_cache: HashMap::new(),
            process_name_cache: HashMap::new(),
            last_inode_refresh: now,
            last_traffic_update: now,
            interface_traffic_history: (0, 0, now),
            total_interface_speed: (0, 0),
            debug,
        }
    }

    /// Check if we have permissions to read /proc/net/tcp
    pub fn check_permissions() -> Result<(), String> {
        // Test read /proc/net/tcp
        if fs::metadata("/proc/net/tcp").is_err() {
            return Err("Cannot read /proc/net/tcp".to_string());
        }

        // Test enumerate processes
        match procfs::process::all_processes() {
            Ok(mut procs) => {
                // Try to read at least one process
                if procs.next().is_none() {
                    return Err("Cannot enumerate processes in /proc".to_string());
                }
            }
            Err(e) => return Err(format!("Cannot access /proc: {}", e)),
        }

        Ok(())
    }

    pub fn update(&mut self) -> Vec<ConnectionInfo> {
        let filter = ConnectionFilter::new();
        self.update_with_filter(&filter).0
    }

    pub fn update_with_filter(&mut self, filter: &ConnectionFilter) -> (Vec<ConnectionInfo>, NetworkStats) {
        let now = Instant::now();

        // 1. Refresh System Info (Process list & Net stats)
        self.sys.refresh_processes();

        // Optimize: Rebuild inode cache every 2 seconds
        if now.duration_since(self.last_inode_refresh) > Duration::from_secs(2) {
            self.rebuild_inode_cache();
            self.last_inode_refresh = now;
        }

        // 2. Calculate Interface Speeds (network traffic, not disk I/O!)
        self.calculate_interface_speeds(now);

        // 3. Scan Sockets with graceful error handling
        let mut connections = Vec::new();

        // TCP IPv4 - gracefully handle errors
        match procfs::net::tcp() {
            Ok(tcp) => {
                for entry in tcp {
                    connections.push(self.map_tcp(entry, "TCP"));
                }
            }
            Err(e) => eprintln!("Warning: Failed to read TCP connections: {}", e),
        }

        // TCP IPv6
        match procfs::net::tcp6() {
            Ok(tcp6) => {
                for entry in tcp6 {
                    connections.push(self.map_tcp(entry, "TCP6"));
                }
            }
            Err(e) => eprintln!("Warning: Failed to read TCP6 connections: {}", e),
        }

        // UDP IPv4
        match procfs::net::udp() {
            Ok(udp) => {
                for entry in udp {
                    connections.push(self.map_udp(entry, "UDP"));
                }
            }
            Err(e) => eprintln!("Warning: Failed to read UDP connections: {}", e),
        }

        // UDP IPv6
        match procfs::net::udp6() {
            Ok(udp6) => {
                for entry in udp6 {
                    connections.push(self.map_udp(entry, "UDP6"));
                }
            }
            Err(e) => eprintln!("Warning: Failed to read UDP6 connections: {}", e),
        }

        // Apply tcpdump-style filters
        connections.retain(|c| filter.matches(c));

        // Calculate statistics
        let stats = self.calculate_stats(&connections);

        (connections, stats)
    }

    fn calculate_stats(&self, connections: &[ConnectionInfo]) -> NetworkStats {
        let mut stats = NetworkStats::default();
        let mut unique_pids = HashSet::new();

        stats.total_connections = connections.len();

        for conn in connections {
            // Count by protocol
            if conn.protocol.contains("TCP") {
                stats.tcp_connections += 1;
            } else if conn.protocol.contains("UDP") {
                stats.udp_connections += 1;
            }

            // Sum bandwidth
            stats.total_upload_speed += conn.upload_speed;
            stats.total_download_speed += conn.download_speed;

            // Track unique processes
            if let Some(pid) = conn.pid {
                unique_pids.insert(pid);
            }
        }

        stats.unique_processes = unique_pids.len();
        stats
    }

    fn calculate_interface_speeds(&mut self, now: Instant) {
        // Refresh network interface statistics
        self.networks.refresh();

        // Sum all network traffic across all interfaces (excluding loopback)
        let mut total_rx: u64 = 0;
        let mut total_tx: u64 = 0;

        for (interface_name, data) in &self.networks {
            // Skip loopback interface
            if interface_name == "lo" {
                continue;
            }

            let rx = data.received();
            let tx = data.transmitted();

            if self.debug {
                eprintln!(
                    "[DEBUG] Interface {}: RX={} bytes, TX={} bytes",
                    interface_name, rx, tx
                );
            }

            total_rx += rx;
            total_tx += tx;
        }

        // Calculate speed delta
        let (prev_rx, prev_tx, prev_time) = self.interface_traffic_history;
        let time_delta = now.duration_since(prev_time).as_secs_f64();

        if time_delta > 0.0 {
            let rx_speed = ((total_rx.saturating_sub(prev_rx)) as f64 / time_delta) as u64;
            let tx_speed = ((total_tx.saturating_sub(prev_tx)) as f64 / time_delta) as u64;
            self.total_interface_speed = (rx_speed, tx_speed);

            if self.debug {
                eprintln!(
                    "[DEBUG] Total speeds: Download={} B/s ({:.2} KB/s), Upload={} B/s ({:.2} KB/s)",
                    rx_speed,
                    rx_speed as f64 / 1024.0,
                    tx_speed,
                    tx_speed as f64 / 1024.0
                );
            }
        }

        self.interface_traffic_history = (total_rx, total_tx, now);
        self.last_traffic_update = now;
    }

    fn rebuild_inode_cache(&mut self) {
        self.inode_cache.clear();
        // Iterate all processes in /proc via procfs to find FDs
        match procfs::process::all_processes() {
            Ok(procs) => {
                for p_res in procs {
                    if let Ok(p) = p_res {
                        // Skip processes we can't read (permission denied is common)
                        if let Ok(fds) = p.fd() {
                            for fd_res in fds {
                                if let Ok(fd) = fd_res {
                                    if let procfs::process::FDTarget::Socket(inode) = fd.target {
                                        self.inode_cache.insert(inode, p.pid as u32);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Warning: Failed to enumerate processes: {}", e),
        }
    }

    fn get_proc_info(&self, inode: u64) -> (Option<u32>, String, String) {
        // Special handling for kernel sockets
        if inode == 0 {
            return (None, "System/Kernel".to_string(), "Kernel socket".to_string());
        }

        if let Some(&pid) = self.inode_cache.get(&inode) {
            let (name, cmd_path) = self.sys.process(Pid::from_u32(pid))
                .map(|p| {
                    let name = p.name().to_string();
                    let cmd = p.cmd().join(" ");
                    let path = if cmd.is_empty() { name.clone() } else { cmd };
                    (name, path)
                })
                .unwrap_or_else(|| {
                    if self.debug {
                        eprintln!("[DEBUG] PID {} found in inode cache but not in process list", pid);
                    }
                    ("System / Elevated".to_string(), "Access Restricted".to_string())
                });

            (Some(pid), name, cmd_path)
        } else {
            if self.debug {
                eprintln!("[DEBUG] Inode {} not found in cache (may need elevated permissions)", inode);
            }
            (None, "System / Elevated".to_string(), "Access Restricted (requires sudo)".to_string())
        }
    }
// ... map_tcp and map_udp remain same but need to match logic context


    fn map_tcp(&self, entry: TcpNetEntry, proto: &str) -> ConnectionInfo {
        let (pid, name, cmd_path) = self.get_proc_info(entry.inode);
        let local_display = simplify_address(&entry.local_address);
        let remote_display = simplify_address(&entry.remote_address);
        let is_localhost = entry.local_address.ip().is_loopback()
            || entry.remote_address.ip().is_loopback();

        // Wireshark-style protocol detection
        let detected_proto = if entry.remote_address.port() != 0 {
            detect_protocol(entry.remote_address.port(), proto)
        } else {
            detect_protocol(entry.local_address.port(), proto)
        };

        // Only show speeds for ESTABLISHED connections
        // For Listen/TimeWait/etc, always show 0
        // Note: We show TOTAL interface speeds here as we cannot track per-connection
        // without eBPF. This is an approximation.
        let (down, up) = match entry.state {
            procfs::net::TcpState::Established => {
                // Show total interface speeds for established connections
                // NOTE: This is an approximation! Without eBPF, we cannot easily track per-connection bandwidth.
                // We assign the TOTAL interface traffic to *every* active connection to show *some* activity.
                // This is slightly misleading but effectively shows when the system is busy.
                self.total_interface_speed
            }
            _ => (0, 0), // Listen, TimeWait, etc. don't have active traffic
        };

        ConnectionInfo {
            pid,
            process_name: name,
            command_path: cmd_path,
            protocol: detected_proto,
            local_addr: entry.local_address,
            remote_addr: entry.remote_address,
            local_addr_display: local_display,
            remote_addr_display: remote_display,
            state: format!("{:?}", entry.state),
            inode: entry.inode,
            upload_speed: up,
            download_speed: down,
            is_localhost,
        }
    }

    fn map_udp(&self, entry: UdpNetEntry, proto: &str) -> ConnectionInfo {
        let (pid, name, cmd_path) = self.get_proc_info(entry.inode);
        let local_display = simplify_address(&entry.local_address);
        let remote_display = simplify_address(&entry.remote_address);
        let is_localhost = entry.local_address.ip().is_loopback()
            || entry.remote_address.ip().is_loopback();

        // Wireshark-style protocol detection
        let detected_proto = if entry.remote_address.port() != 0 {
            detect_protocol(entry.remote_address.port(), proto)
        } else {
            detect_protocol(entry.local_address.port(), proto)
        };

        // UDP connections with a specific remote address might be active
        // If remote is unspecified (*), it's likely just listening
        let (down, up) = if entry.remote_address.ip().is_unspecified() {
            (0, 0) // Listening UDP socket
        } else {
            self.total_interface_speed // Active UDP connection
        };

        ConnectionInfo {
            pid,
            process_name: name,
            command_path: cmd_path,
            protocol: detected_proto,
            local_addr: entry.local_address,
            remote_addr: entry.remote_address,
            local_addr_display: local_display,
            remote_addr_display: remote_display,
            state: "UDP".to_string(), // UDP is stateless
            inode: entry.inode,
            upload_speed: up,
            download_speed: down,
            is_localhost,
        }
    }
}
