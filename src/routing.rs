use crate::config::Route;
use std::{collections::HashMap, net::IpAddr};

// ==========================================
// 3. SMART PORT MAPPING & SNI ROUTING
// ==========================================
pub fn parse_port_mappings(mappings: &[String], location: Option<&str>, routes: &mut HashMap<String, Route>) {
    for m in mappings {
        let (left, right) = if let Some(idx) = m.find('=') {
            (&m[..idx], &m[idx+1..])
        } else if let Some(idx) = m.rfind(':') {
            (&m[..idx], &m[idx+1..])
        } else {
            continue;
        };
        let right = right.trim().to_string();
        let left = left.trim();
        
        let mut bind_ip = "0.0.0.0".to_string();
        let mut sni_rule = None;
        let mut start_port = 0;
        let mut end_port = 0;

        let parts: Vec<&str> = left.split(':').collect();
        if parts.len() == 2 {
            if let (Ok(s), Ok(e)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                start_port = s;
                end_port = e;
            } else {
                let host = parts[0];
                if host.parse::<IpAddr>().is_ok() || host == "localhost" {
                    bind_ip = host.to_string();
                } else {
                    sni_rule = Some(host.to_string());
                }
                start_port = parts[1].parse::<u16>().unwrap_or(0);
                end_port = start_port;
            }
        } else if parts.len() == 1 {
            start_port = parts[0].parse::<u16>().unwrap_or(0);
            end_port = start_port;
        } else if parts.len() == 3 {
            let host = parts[0];
            if host.parse::<IpAddr>().is_ok() || host == "localhost" {
                bind_ip = host.to_string();
            } else {
                sni_rule = Some(host.to_string());
            }
            start_port = parts[1].parse::<u16>().unwrap_or(0);
            end_port = parts[2].parse::<u16>().unwrap_or(0);
        }

        if start_port == 0 || end_port < start_port {
            continue;
        }

        let mut target_start = 0;
        let mut target_end = 0;
        let right_parts: Vec<&str> = right.split(':').collect();
        let is_right_range = right_parts.len() == 2 && right_parts[0].parse::<u16>().is_ok() && right_parts[1].parse::<u16>().is_ok();
        
        if is_right_range {
            target_start = right_parts[0].parse::<u16>().unwrap();
            target_end = right_parts[1].parse::<u16>().unwrap();
        }

        for i in 0..=(end_port - start_port) {
            let current_port = start_port + i;
            let bind_addr = format!("{}:{}", bind_ip, current_port);
            let route = routes.entry(bind_addr).or_default();
            
            let current_right = if is_right_range {
                let tp = std::cmp::min(target_start + i, target_end);
                tp.to_string()
            } else {
                right.clone()
            };

            if let Some(sni) = &sni_rule {
                route.sni_rules.insert(sni.clone(), current_right.clone());
            } else {
                route.default_upstream = Some(current_right.clone());
            }
            if let Some(loc) = location {
                route.target_locations.insert(current_right, loc.to_string());
            }
        }
    }
}

pub fn parse_server_sni_proxy(
    configs: &[crate::config::SniProxyConfig],
    global_bind: &str,
    routes: &mut HashMap<String, Route>,
) {
    let default_port = global_bind.split(':').last().unwrap_or("443").parse::<u16>().unwrap_or(443);

    for cfg in configs {
        let target_str = cfg.target.join(",");
        
        for incoming in &cfg.incoming_sni {
            let mut sni = incoming.clone();
            let mut port = default_port;
            let mut bind_ip = "0.0.0.0".to_string();

            if let Some(idx) = incoming.rfind(':') {
                let port_str = &incoming[idx + 1..];
                if let Ok(p) = port_str.parse::<u16>() {
                    port = p;
                    sni = incoming[..idx].to_string();
                }
            }

            let mut sni_rule = None;
            if sni.parse::<IpAddr>().is_ok() || sni == "localhost" {
                bind_ip = sni;
            } else if !sni.is_empty() {
                sni_rule = Some(sni);
            }

            let bind_addr = format!("{}:{}", bind_ip, port);
            let route = routes.entry(bind_addr).or_default();

            if let Some(s) = sni_rule {
                route.sni_rules.insert(s, target_str.clone());
            } else {
                route.default_upstream = Some(target_str.clone());
            }
        }
    }
}

// استخراج SNI از داخل پکت‌های خام TLS (بدون دستکاری پکت)
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let mut pos = 0;
    if buf.len() < 5 || buf[0] != 0x16 { return None; } // Not a Handshake
    pos += 5;
    if buf.len() < pos + 4 || buf[pos] != 0x01 { return None; } // Not ClientHello
    pos += 38; // Skip to Session ID
    if buf.len() <= pos { return None; }

    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if buf.len() <= pos + 1 { return None; }

    let cipher_suites_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
    pos += 2 + cipher_suites_len;
    if buf.len() <= pos { return None; }

    let comp_methods_len = buf[pos] as usize;
    pos += 1 + comp_methods_len;
    if buf.len() <= pos + 1 { return None; }

    let ext_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
    pos += 2;
    let ext_end = pos + ext_len;
    if buf.len() < ext_end { return None; }

    while pos + 4 <= ext_end {
        let ext_type = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
        let ext_size = ((buf[pos + 2] as usize) << 8) | (buf[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 { // SNI Extension
            if pos + 2 > ext_end { return None; }
            let sni_list_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
            let mut sni_pos = pos + 2;
            let list_end = sni_pos + sni_list_len;

            while sni_pos + 3 <= list_end {
                let name_type = buf[sni_pos];
                let name_len = ((buf[sni_pos + 1] as usize) << 8) | (buf[sni_pos + 2] as usize);
                sni_pos += 3;
                if name_type == 0x00 { // Hostname
                    if sni_pos + name_len <= list_end {
                        if let Ok(sni) = std::str::from_utf8(&buf[sni_pos..sni_pos + name_len]) {
                            return Some(sni.to_string());
                        }
                    }
                    break;
                }
                sni_pos += name_len;
            }
            break;
        }
        pos += ext_size;
    }
    None
}

pub fn is_http_request(buf: &[u8]) -> bool {
    let methods: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", 
        b"DELETE ", b"PATCH ", b"TRACE ", b"CONNECT "
    ];
    for &m in methods {
        if buf.starts_with(m) {
            return true;
        }
    }
    false
}

pub fn extract_http_host(buf: &[u8]) -> Option<String> {
    if !is_http_request(buf) {
        return None;
    }
    
    let mut host_start = None;
    for i in 0..buf.len().saturating_sub(6) {
        if buf[i] == b'\n' {
            let j = i + 1;
            if j + 5 <= buf.len() {
                let prefix = &buf[j..j+5];
                if prefix.eq_ignore_ascii_case(b"Host:") {
                    host_start = Some(j + 5);
                    break;
                }
            }
        }
    }
    
    // Check if the very first line is Host: (rare, but valid in some tests)
    if host_start.is_none() && buf.len() >= 5 && buf[0..5].eq_ignore_ascii_case(b"Host:") {
        host_start = Some(5);
    }
    
    if let Some(mut start) = host_start {
        while start < buf.len() && (buf[start] == b' ' || buf[start] == b'\t') {
            start += 1;
        }
        
        let mut end = start;
        while end < buf.len() && buf[end] != b'\r' && buf[end] != b'\n' {
            end += 1;
        }
        
        if end > start {
            if let Ok(host_val) = std::str::from_utf8(&buf[start..end]) {
                let mut host = host_val.trim().to_string();
                
                // Strip port if present
                if let Some(colon_idx) = host.rfind(':') {
                    let num_colons = host.chars().filter(|c| *c == ':').count();
                    if num_colons == 1 {
                        host.truncate(colon_idx);
                    } else if let Some(close_bracket) = host.rfind(']') {
                        if colon_idx > close_bracket {
                            host.truncate(colon_idx);
                        }
                    }
                }
                return Some(host.to_lowercase());
            }
        }
    }
    None
}
