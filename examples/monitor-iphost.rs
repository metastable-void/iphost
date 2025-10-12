use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iphost::{AutoIpHostResolver, IpHost};

use std::fmt::Arguments;

fn print_event(args: Arguments<'_>) {
    println!(
        "[{:.3}] {}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as f64 / 1000.0f64,
        args.to_string(),
    );
}

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

    let ip_host_clone = ip_host.clone();

    print_event(format_args!("Monitoring address changes for hostname: {}", &ip_host));
    let resolver = AutoIpHostResolver::new(ip_host, Duration::from_secs(1));

    #[cfg(not(feature = "broadcast"))]
    let mut ipv4 = None;

    #[cfg(not(feature = "broadcast"))]
    let mut ipv6 = None;

    #[cfg(not(feature = "broadcast"))]
    loop {
        let new_ipv4 = resolver.ipv4_addr();
        if new_ipv4 != ipv4 {
            if let Some(v4) = new_ipv4 {
                print_event(format_args!("<{}> new_v4 = {}", &ip_host_clone, v4));
            } else {
                print_event(format_args!("<{}> new_v4 = (none)", &ip_host_clone));
            }
            ipv4 = new_ipv4;
        }

        let new_ipv6 = resolver.ipv6_addr();
        if new_ipv6 != ipv6 {
            if let Some(v6) = new_ipv6 {
                print_event(format_args!("<{}> new_v6 = {}", &ip_host_clone, v6));
            } else {
                print_event(format_args!("<{}> new_v6 = (none)", &ip_host_clone));
            }
            ipv6 = new_ipv6;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    #[cfg(feature = "broadcast")]
    {
        let subscriber = resolver.subscribe_changes();
        loop {
            if let Some(changes) = subscriber.wait_for_change_blocking() {
                if let Some(v4_change) = changes.v4_change() {
                    if let Some(v4_addr) = v4_change {
                        print_event(format_args!("<{}> new_v4 = {}", &ip_host_clone, v4_addr));
                    } else {
                        print_event(format_args!("<{}> new_v4 = (none)", &ip_host_clone));
                    }
                }
                if let Some(v6_change) = changes.v6_change() {
                    if let Some(v6_addr) = v6_change {
                        print_event(format_args!("<{}> new_v6 = {}", &ip_host_clone, v6_addr));
                    } else {
                        print_event(format_args!("<{}> new_v6 = (none)", &ip_host_clone));
                    }
                }
            } else {
                print_event(format_args!("Error: Resolver exited"));
                std::process::exit(1);
            }
        }
    }
}
