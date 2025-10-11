
use iphost::{IpHost, IpHostResolver};

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
    let resolver = IpHostResolver::new(ip_host);
    println!("Resolved IP addresses on system-returned order:");
    for addr in resolver.resolve() {
        println!("  {}", addr);
    }
}
