use chrono::DateTime;
use firal::db;
use firal::model::Entry;
use postgres::Connection;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, PartialEq)]
struct OutOfBounds;

impl fmt::Display for OutOfBounds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "out of bounds access")
    }
}

impl Error for OutOfBounds {
    fn description(&self) -> &str {
        "out of bounds access"
    }
    fn cause(&self) -> Option<&Error> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "firal")]
struct Opt {
    /// The path to the firewall logs
    #[structopt(short = "f", long = "file", parse(from_os_str), required = true)]
    file: PathBuf,
}

fn insert_line(db_conn: &Connection, parsed: HashMap<&str, &str>) {
    let mut entry = Entry::new();
    for (k, v) in parsed {
        match k {
            "ID" => entry.packet_id = v.parse::<i32>().unwrap(),
            "IN" => entry.in_interface = v.to_string(),
            "OUT" => entry.out_interface = Some(v.to_string()),
            "SRC" => entry.src_ip = v.to_string(),
            "DST" => entry.dst_ip = v.to_string(),
            "LEN" => entry.packet_size = v.parse::<i32>().unwrap(),
            "PROTO" => entry.protocol = v.to_string(),
            "SPT" => entry.src_port = v.parse::<i32>().unwrap(),
            "DPT" => entry.dst_port = v.parse::<i32>().unwrap(),
            "RULE_ID" => entry.rule_id = v.to_string(),
            "FLOW_TYPE" => entry.flow_type = v.to_string(),
            "FW_ACTION" => entry.fw_action = v.to_string(),
            "LOGGED_AT" => entry.logged_at = Some(DateTime::parse_from_rfc3339(v).unwrap()),
            _ => {
                if cfg!(debug_assertions) {
                    eprintln!("ignored: {}", k);
                }
            },
        }
    }

    match db_conn.execute(
        "INSERT INTO entries(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet_id,
            packet_size,
            protocol,
            flow_type,
            rule_id,
            out_interface,
            in_interface,
            logged_at)
        VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        &[
            &entry.src_ip,
            &entry.src_port,
            &entry.dst_ip,
            &entry.dst_port,
            &entry.packet_id,
            &entry.packet_size,
            &entry.protocol,
            &entry.flow_type,
            &entry.rule_id,
            &entry.out_interface,
            &entry.in_interface,
            &entry.logged_at,
        ],
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to insert entry: {:?}: {}", entry, e);

            // .execute returns a u64 to represent the number of rows updated
            // the return type must match so we also return the same.
            0
        },
    };
}

fn parse_brackets(bracket: &str) -> Result<(&str, &str, &str, &str), OutOfBounds> {
    let split_end_bracket: Vec<&str> = bracket.split(']').collect();
    let split_inner: Vec<&str> = split_end_bracket
        .get(0)
        .ok_or(OutOfBounds)?
        .split('-')
        .collect();
    let in_interface: Vec<&str> = split_end_bracket
        .get(1)
        .ok_or(OutOfBounds)?
        .split('=')
        .collect();

    Ok((
        &split_inner[0].get(1..).ok_or(OutOfBounds)?,
        split_inner.get(1).ok_or(OutOfBounds)?,
        split_inner.get(2).ok_or(OutOfBounds)?,
        in_interface.get(1).ok_or(OutOfBounds)?,
    ))
}

fn parse_line(line: &str) -> Result<HashMap<&str, &str>, OutOfBounds> {
    let line_arr = line.split(' ');
    let mut parsed = HashMap::new();
    for (i, data) in line_arr.enumerate() {
        match i {
            0 => {
                parsed.insert("LOGGED_AT", data);
            },
            1 | 2 => {},
            3 => {
                let (flow_type, rule_id, fw_action, in_interface) = match parse_brackets(data) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(e);
                    }
                };
                parsed.insert("FW_ACTION", fw_action);
                parsed.insert("RULE_ID", rule_id);
                parsed.insert("FLOW_TYPE", flow_type);
                parsed.insert("IN", in_interface);
            },
            _ => {
                let kv: Vec<&str> = data.split('=').collect();
                if kv.len() < 2 {
                    if cfg!(debug_assertions) {
                        eprintln!("ignored: {}", kv[0]);
                    }
                    continue;
                }
                parsed.insert(kv[0], kv[1]);
            },
        };
    }
    Ok(parsed)
}

fn ingest_file(file: PathBuf, db_conn: &Connection) -> Result<(), Box<dyn Error>> {
    let content = fs::read_to_string(file)?;
    for line in content.lines() {
        match parse_line(line) {
            Ok(entry) => {
                insert_line(db_conn, entry);
            },
            Err(err) => {
                eprintln!("skipped line ({}), error: {}", line, err);
            },
        };
    }
    Ok(())
}

fn main() {
    let opt = Opt::from_args();
    let db_conn = db::init().unwrap();
    match ingest_file(opt.file, &db_conn) {
        Ok(_) => {},
        Err(e) => eprintln!("ingest failed with: {}", e),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_brackets_happy_path() {
        let good_brackets = "[LAN_IN-4001-A]IN=eth1";
        let expected = ("LAN_IN", "4001", "A", "eth1");
        let actual = parse_brackets(good_brackets).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_brackets_unknown_line() {
        let bad_brackets = "IPv4: martian source 0.0.0.0 from 0.0.0.0, on dev eth0";
        let expected = Err(OutOfBounds);
        let actual =  parse_brackets(bad_brackets);
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_line_happy_path() {
        let good_line = "2019-01-12T13:56:05-08:00 host kernel: \
                         [LAN_LOCAL-default-A]IN=eth0 OUT= \
                         MAC=00:00:00:00:00:00:00:00:00:00:00:00:00:00 \
                         SRC=192.168.1.8 DST=192.168.1.1 LEN=52 TOS=0x00 PREC=0x00 \
                         TTL=64 ID=40048 DF PROTO=TCP SPT=8080 DPT=45117 WINDOW=280 RES=0x00 ACK URGP=0";
        let mut expected: HashMap<&str, &str> = HashMap::new();
        expected.insert("ID", "40048");
        expected.insert("IN", "eth0");
        expected.insert("OUT", "");
        expected.insert("SRC", "192.168.1.8");
        expected.insert("DST", "192.168.1.1");
        expected.insert("LEN", "52");
        expected.insert("PROTO", "TCP");
        expected.insert("SPT", "8080");
        expected.insert("DPT", "45117");
        expected.insert("RULE_ID", "default");
        expected.insert("FLOW_TYPE", "LAN_LOCAL");
        expected.insert("FW_ACTION", "A");
        expected.insert("LOGGED_AT", "2019-01-12T13:56:05-08:00");
        expected.insert("MAC", "00:00:00:00:00:00:00:00:00:00:00:00:00:00");
        expected.insert("TOS", "0x00");
        expected.insert("PREC", "0x00");
        expected.insert("TTL", "64");
        expected.insert("WINDOW", "280");
        expected.insert("RES", "0x00");
        expected.insert("URGP", "0");
        let actual = parse_line(good_line).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_line_unknown_line() {
        let bad_line = "IPv4: martian source 0.0.0.0 from 0.0.0.0, on dev eth0";
        let expected = Err(OutOfBounds);
        let actual = parse_line(bad_line);
        assert_eq!(expected, actual);
    }
}
