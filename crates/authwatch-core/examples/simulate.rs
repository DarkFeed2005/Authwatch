//! Append realistic auth.log lines to a file so you can test AuthWatch without a real attack.
//!
//!   cargo run -p authwatch-core --example simulate -- ./test-auth.log all
//!
//! Scenarios: brute | spray | compromise | useradd | sudo | all

use chrono::Local;
use std::{fs::OpenOptions, io::Write, thread::sleep, time::Duration};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "test-auth.log".into());
    let scenario = args.next().unwrap_or_else(|| "all".into());
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

    let mut emit = |msg: String| -> std::io::Result<()> {
        // Classic syslog timestamp, e.g. "Oct 12 10:15:01"
        let line = format!("{} testhost {}\n", Local::now().format("%b %e %H:%M:%S"), msg);
        file.write_all(line.as_bytes())?;
        file.flush()?;
        print!("+ {line}");
        sleep(Duration::from_millis(150));
        Ok(())
    };
    let run = |s: &str| scenario == "all" || scenario == s;

    if run("brute") {
        for i in 0..8 {
            emit(format!("sshd[{}]: Failed password for root from 203.0.113.50 port {} ssh2", 4000 + i, 40000 + i))?;
        }
    }
    if run("spray") {
        for (i, u) in ["admin", "oracle", "postgres", "ubuntu", "test", "git"].iter().enumerate() {
            emit(format!(
                "sshd[{}]: Failed password for invalid user {u} from 198.51.100.77 port {} ssh2",
                5000 + i, 41000 + i
            ))?;
        }
    }
    if run("compromise") {
        for i in 0..4 {
            emit(format!("sshd[{}]: Failed password for deploy from 192.0.2.99 port {} ssh2", 6000 + i, 42000 + i))?;
        }
        emit("sshd[6100]: Accepted password for deploy from 192.0.2.99 port 42100 ssh2".into())?;
    }
    if run("useradd") {
        emit("useradd[7000]: new user: name=support2, UID=1005, GID=1005, home=/home/support2, shell=/bin/bash".into())?;
    }
    if run("sudo") {
        emit("sudo:    alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow".into())?;
        emit("sudo:    alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash".into())?;
        emit("sudo:    alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update".into())?;
    }
    Ok(())
}
