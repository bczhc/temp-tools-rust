use bytesize::ByteSize;
use clap::{Arg, Command};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use once_cell::sync::Lazy;
use std::fs::File;
use std::io::{Read, Write};
use std::process::Stdio;
use std::sync::RwLock;
use std::thread::{sleep, spawn};
use std::time::Duration;
use systemstat::{Platform, System};
use toml::Value;

static CONFIGS: Lazy<RwLock<Option<Configs>>> = Lazy::new(|| RwLock::new(None));
static INIT_TX_BYTES: Lazy<RwLock<u64>> = Lazy::new(|| RwLock::new(0));
static ARGUMENTS: Lazy<RwLock<Arguments>> = Lazy::new(|| RwLock::new(Arguments::default()));
static LIMIT_CHECKER: Lazy<RwLock<Option<LimitChecker>>> = Lazy::new(|| RwLock::new(None));

macro_rules! rw_read {
    ($x:expr) => {
        $x.read().unwrap()
    };
}

macro_rules! rw_write {
    ($x:expr) => {
        $x.write().unwrap()
    };
}

fn main() {
    let interfaces = interfaces::Interface::get_all().unwrap();
    let interfaces = interfaces
        .iter()
        .map(|x| x.name.as_str())
        .collect::<Vec<_>>();

    let matches = Command::new("check-net-traffic")
        .arg(
            Arg::new("interface")
                .takes_value(true)
                .possible_values(interfaces)
                .required(true)
                .short('i')
                .long("interface"),
        )
        .arg(
            Arg::new("config-file")
                .required(true)
                .takes_value(true)
                .short('c')
                .long("config"),
        )
        .arg(
            Arg::new("interval")
                .required(false)
                .takes_value(true)
                .default_value("2000")
                .help("monitoring interval (in ms)")
                .short('t')
                .long("interval"),
        )
        .arg(
            Arg::new("cmd")
                .help("command to run when reaching final-size")
                .required(false)
                .multiple_values(true),
        )
        .get_matches();

    rw_write!(CONFIGS).replace(read_config(matches.value_of("config-file").unwrap()));

    let interface = matches.value_of("interface").unwrap();

    {
        let mut write_guard = ARGUMENTS.write().unwrap();
        write_guard.interface = String::from(interface);
        write_guard.interval = matches.value_of("interval").unwrap().parse().unwrap();
        write_guard.cmd = matches
            .values_of("cmd")
            .map(|x| x.map(String::from).collect::<Vec<_>>());
    }

    register_signal_handlers();
    start_monitoring();
}

fn register_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGUSR1, sigusr1_handler as libc::sighandler_t);
        libc::signal(libc::SIGUSR2, sigusr2_handler as libc::sighandler_t);
    }
}

/// reset traffic counter
fn sigusr1_handler() {
    println!("SIGUSR1 received, reset initial tx_byte");
    *rw_write!(INIT_TX_BYTES) = current_tx_bytes();
    {
        let mut guard = rw_write!(LIMIT_CHECKER);
        guard.as_mut().unwrap().reset();
    }
}

/// write current used tx bytes to file
fn sigusr2_handler() {
    let used_tx_bytes = current_tx_bytes() - *rw_read!(INIT_TX_BYTES);
    let mut file = File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open("current_tx_bytes")
        .unwrap();
    file.write_all(used_tx_bytes.to_string().as_bytes())
        .unwrap();
}

fn start_monitoring() {
    let configs;
    {
        let read_guard = rw_read!(CONFIGS);
        configs = read_guard.as_ref().unwrap().clone();
    }

    *rw_write!(INIT_TX_BYTES) = current_tx_bytes();
    let interval = rw_read!(ARGUMENTS).interval;

    rw_write!(LIMIT_CHECKER).replace(LimitChecker::new(&configs.notify_limits));

    loop {
        let init_tx_bytes = *rw_read!(INIT_TX_BYTES);

        let tx_bytes = current_tx_bytes();
        let used_tx_bytes = tx_bytes - init_tx_bytes;

        println!(
            "used tx data: {}",
            ByteSize(used_tx_bytes).to_string_as(true)
        );

        let check = {
            let mut guard = rw_write!(LIMIT_CHECKER);
            guard.as_mut().unwrap().check(used_tx_bytes)
        };
        match check {
            None => {}
            Some(limit_byte) => {
                spawn(move || {
                    println!("sending email...");
                    send_email(
                        "network use alert!!!",
                        format!(
                            "Over limit! tx limit: {}",
                            ByteSize(limit_byte).to_string_as(true),
                        ),
                    );
                    println!("email sent");
                });
            }
        }

        if used_tx_bytes >= configs.final_limit {
            let read_guard = rw_read!(ARGUMENTS);
            match &read_guard.cmd {
                None => {}
                Some(cmd) => {
                    let program = &cmd[0];
                    let args = &cmd[1..];

                    let mut child = std::process::Command::new(program)
                        .args(args)
                        .stdin(Stdio::inherit())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .unwrap();

                    if !child.wait().unwrap().success() {
                        panic!("Program exits with non-zero exit value")
                    }
                }
            }
            break;
        }

        sleep(Duration::from_millis(interval));
    }
}

fn current_tx_bytes() -> u64 {
    let system = System::new();
    let stat = system
        .network_stats(&rw_read!(ARGUMENTS).interface)
        .unwrap();
    stat.tx_bytes.0
}

fn send_email(subject: &str, content: String) {
    let email_configs;
    {
        let read_guard = rw_read!(CONFIGS);
        email_configs = read_guard.as_ref().unwrap().email.clone();
    }

    let credentials = Credentials::new(
        email_configs.username.clone(),
        email_configs.password.clone(),
    );

    let message = Message::builder()
        .from(email_configs.from.parse().unwrap())
        .to(email_configs.to.parse().unwrap())
        .subject(subject)
        .body(content)
        .unwrap();

    let smtp_transport = SmtpTransport::relay(&email_configs.smtp)
        .unwrap()
        .credentials(credentials)
        .build();

    smtp_transport.send(&message).unwrap();
}

fn read_config(config_file: &str) -> Configs {
    let mut read = String::new();
    File::open(config_file)
        .unwrap()
        .read_to_string(&mut read)
        .unwrap();

    let configs: Value = toml::from_str(&read).unwrap();

    let email = &configs["email"];
    let limit = &configs["limit"];

    Configs {
        email: EmailConfigs {
            username: String::from(email["username"].as_str().unwrap()),
            password: String::from(email["password"].as_str().unwrap()),
            from: String::from(email["from"].as_str().unwrap()),
            to: String::from(email["to"].as_str().unwrap()),
            smtp: String::from(email["smtp"].as_str().unwrap()),
        },
        notify_limits: limit["notify-size"]
            .as_str()
            .unwrap()
            .split(',')
            .take_while(|x| !x.is_empty())
            .map(|x| x.trim().parse::<ByteSize>().unwrap().0)
            .collect::<Vec<_>>(),
        final_limit: limit["final-size"]
            .as_str()
            .unwrap()
            .parse::<ByteSize>()
            .unwrap()
            .0,
    }
}

#[derive(Clone)]
struct EmailConfigs {
    smtp: String,
    username: String,
    password: String,
    from: String,
    to: String,
}

#[derive(Clone)]
struct Configs {
    email: EmailConfigs,
    notify_limits: Vec<u64>,
    final_limit: u64,
}

#[derive(Default)]
struct Arguments {
    interface: String,
    interval: u64,
    cmd: Option<Vec<String>>,
}

struct LimitChecker {
    limits: Vec<u64>,
    compared_index: usize,
}

impl LimitChecker {
    fn new(limits: &[u64]) -> LimitChecker {
        LimitChecker {
            limits: {
                let mut v = vec![0_u64];
                for x in limits {
                    v.push(*x);
                }
                v
            },
            compared_index: 0,
        }
    }

    fn check(&mut self, used_size: u64) -> Option<u64> {
        let new_index = if used_size > self.limits[self.compared_index] {
            let mut i = self.compared_index;
            while i < self.limits.len() && self.limits[i] <= used_size {
                i += 1;
            }
            i - 1
        } else {
            self.compared_index
        };

        if new_index != self.compared_index {
            self.compared_index = new_index;
            return Some(self.limits[new_index]);
        }
        None
    }

    fn reset(&mut self) {
        self.compared_index = 0;
    }
}
