use postgres::{Connection, TlsMode};
use std::env;
use std::error::Error;

pub fn init() -> Result<Connection, Box<Error>> {
    let db_user = env::var("FIRAL_USER").expect("FIRAL_USER not set");
    let db_pass = env::var("FIRAL_PASS").expect("FIRAL_PASS not set");
    let db_host = env::var("FIRAL_HOST").expect("FIRAL_HOST not set");
    let db_db = env::var("FIRAL_DB").expect("FIRAL_DB not set");
    let conn = Connection::connect(
        format!(
            "postgres://{}:{}@{}:5432/{}",
            db_user, db_pass, db_host, db_db
        ),
        TlsMode::None,
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries(
            id              BIGSERIAL PRIMARY KEY,
            src_port        INT,
            dst_port        INT,
            packet_id       INT,
            packet_size     INT,
            src_ip          VARCHAR(16),
            dst_ip          VARCHAR(16),
            in_interface    VARCHAR(16),
            out_interface   VARCHAR(16),
            protocol        VARCHAR(16),
            flow_type       VARCHAR(16),
            rule_id         VARCHAR(32),
            logged_at       TIMESTAMP WITH TIME ZONE,
            UNIQUE(src_ip, protocol, packet_id, logged_at)
        )",
        &[],
    )?;

    Ok(conn)
}
