module SumStats;

#implementer sumStats

event zeek_init() {
    SumStats::clear_table(SumStats::Stats);
}

event syn_flood_detected(ip: addr) {
    print fmt("Possible SYN flood detected from %s", ip);
    # Add your custom logic or alerting here
}

event connection_state_remove(c: connection) {
    print c$history;
    if ("i" in c$history) {
        print fmt("Inconsistent packet detected in connection: %s", c$id$orig_h);
    }
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {

    if (is_orig) {
        if ("F" in flags && "R" in flags) {
            print fmt("RST and FIN flags set in an outgoing packet: %s", c$id$orig_h);
            
        }

        if ("P" in flags) {
            print fmt("Ugyldig ACK-flag PSH i en udgående pakke: %s", c$id$orig_h);
            
        }
    } else {
        if ("F" in flags && "R" in flags) {
            print fmt("RST and FIN flags set in an incoming packet: %s", c$id$orig_h);
        }

        if ("U" in flags) {
            print fmt("Ugyldig ACK-flag URG %s", c$id$orig_h);
        } else if ("F" in flags) {
            print fmt("Ugyldig ACK-flag FIN %s", c$id$orig_h);
        }
    }

    if ("RASPUF" in flags) {
        print fmt("Alle flags sat: %s", c$id$orig_h);
    } else if ("0" in flags) {
        print fmt("Ingen flag er sat i en pakke: %s", c$id$orig_h);
    }

  
    if (is_orig && "S" in flags && !"A" in flags) {
        SumStats::add(SumStats::Stats, [$src_ip=c$id$orig_h, $syn_count=1]);
    }

    if (SumStats::sum(SumStats::Stats, [$src_ip=c$id$orig_h], $syn_count) > 250 {
#generer notice hvis der er over 250 SYN pakker.
        syn_flood_detected(c$id$orig_h);
        NOTICE(fmt("Possible SYN flood detected from following IP address %s", c$id$orig_h));
    }
}
