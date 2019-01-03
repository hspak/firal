use chrono;

#[derive(Debug)]
pub struct Entry {
    pub id: i64,
    pub src_ip: String,
    pub src_port: i32,
    pub dst_ip: String,
    pub dst_port: i32,
    pub packet_size: i32,
    pub packet_id: i32,
    pub protocol: String,
    pub flow_type: String,
    pub rule_id: String,
    pub in_interface: String,
    pub out_interface: Option<String>,
    pub fw_action: String,
    pub logged_at: Option<chrono::DateTime<chrono::FixedOffset>>,
}

impl Default for Entry {
    fn default() -> Entry {
        Entry {
            id: 0,
            src_ip: String::new(),
            src_port: 0,
            dst_ip: String::new(),
            dst_port: 0,
            packet_size: 0,
            packet_id: 0,
            protocol: String::new(),
            flow_type: String::new(),
            rule_id: String::new(),
            fw_action: String::new(),
            in_interface: String::new(),
            out_interface: None,
            logged_at: None,
        }
    }
}

impl Entry {
    pub fn new() -> Entry {
        Entry::default()
    }
}
