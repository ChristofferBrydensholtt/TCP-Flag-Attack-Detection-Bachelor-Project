extern crate pcap;
extern crate pnet;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

fn main() {
    let interface = "eth0";

    let mut cap = pcap::Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next() {
        if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
            match ethernet_packet.get_ethertype() {
                IpNextHeaderProtocols::Tcp => {
                    // Kig på TCP pakker
                    let tcp_packet = TcpPacket::new(ethernet_packet.payload());
                    if let Some(tcp_packet) = tcp_packet {
                        let flags = tcp_packet.get_flags();

                        // Check check for RSTFIN pakke
                        if flags & pnet::packet::tcp::TCP_FLAG_RST != 0
                            && flags & pnet::packet::tcp::TCP_FLAG_FIN != 0
                        {
                            println!(
                                "Illegal TCP Flag Combination (RST and FIN): {}:{} > {}:{}; Seq: {}, Ack: {}",
                                ethernet_packet.get_source(),
                                tcp_packet.get_source(),
                                ethernet_packet.get_destination(),
                                tcp_packet.get_destination(),
                                tcp_packet.get_sequence(),
                                tcp_packet.get_acknowledgment()
                            );
                        }

                     
                        println!(
                            "TCP Packet: {}:{} > {}:{}; Seq: {}, Ack: {}, Flags: {:b}",
                            ethernet_packet.get_source(),
                            tcp_packet.get_source(),
                            ethernet_packet.get_destination(),
                            tcp_packet.get_destination(),
                            tcp_packet.get_sequence(),
                            tcp_packet.get_acknowledgment(),
                            flags
                        );
                    }
                }
                _ => {}
            }
        }
    }
}
