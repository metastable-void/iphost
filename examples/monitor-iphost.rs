
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iphost::{IpHost, AutoIpHostResolver};

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        println!("Usage: {} <hostname>", &args[0]);
        std::process::exit(0);
    }

    let ip_host = match args[1].parse::<IpHost>() {
        Ok(h) => h,
        _ => {
            eprintln!("{}: Invalid hostname", &args[0]);
            std::process::exit(1);
        }
    };
    println!("Monitoring address changes for hostname: {}", &ip_host);
    let resolver = AutoIpHostResolver::new(ip_host, Duration::from_secs(1));
    let mut ipv4 = None;
    let mut ipv6 = None;
    loop {
        let new_ipv4 = resolver.ipv4_addr();
        if new_ipv4 != ipv4 {
            println!(
                "[{}] IPv4 changed: {:?}",
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                new_ipv4,
            );
            ipv4 = new_ipv4;
        }

        let new_ipv6 = resolver.ipv6_addr();
        if new_ipv6 != ipv6 {
            println!(
                "[{}] IPv6 changed: {:?}",
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                new_ipv6,
            );
            ipv6 = new_ipv6;
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}
