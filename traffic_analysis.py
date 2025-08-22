import dpkt
import socket
import matplotlib.pyplot as plt
import statistics
import argparse
import ipaddress

def dns_query_response_times(pcap_file: str) -> float:
    """
    Reads a pcap file, extracts DNS query-response pairs,
    computes response times, and returns the median response time (ms).
    """
    query_times = {}
    response_times = []

    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                eth_data = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth_data.data, dpkt.ip.IP):
                    continue
                ip_data = eth_data.data
                if not isinstance(ip_data.data, dpkt.udp.UDP):
                    continue

                udp_data = ip_data.data

                if udp_data.sport != 53 and udp_data.dport != 53:  # DNS usually on port 53
                    continue

                dns = dpkt.dns.DNS(udp_data.data) # DNS data poured onto python object

                # DNS Query
                if dns.qr == dpkt.dns.DNS_Q:  
                    query_times[dns.id] = ts

                # DNS Response
                elif dns.qr == dpkt.dns.DNS_R:  
                    if dns.id in query_times:
                        rtt = (ts - query_times[dns.id]) * 1000  # convert to ms
                        response_times.append(rtt)
                        del query_times[dns.id]

            except (dpkt.UnpackError, ValueError):
                continue

    if not response_times:
        return -1
    return statistics.median(response_times)


def get_pcap_from_file(filename:str)-> any:
    """
    use it for loading information from pcap
    """
    with open(filename, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

    return pcap

def get_ip_from_bytes(ip_bytes: bytes) -> str:
    """
    Convert an IP address in bytes to its string form.
    Automatically detects IPv4 vs IPv6.
    """
    if len(ip_bytes) == 4:   # IPv4 is 4 bytes
        return socket.inet_ntop(socket.AF_INET, ip_bytes)
    elif len(ip_bytes) == 16:  # IPv6 is 16 bytes
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    else:
        raise ValueError(f"Invalid IP length {len(ip_bytes)} (expected 4 for IPv4 or 16 for IPv6)")
    

def get_bytes_from_ip(ip_addr: str) -> bytes:
    """
    Convert an IP address (IPv4/IPv6) to its packed binary form.
    identifies internally if ipv4 or ipv6 and returns the corresponding bytes
    wrapper of the entire situation to cconvert ip_addr to bytes no matter the format
    Args:
        ip_addr (str): The IP address string.
    
    Returns:
        bytes: Packed binary form of the IP address.
    """
    family = socket.AF_INET if is_ipv4(ip_addr) else socket.AF_INET6
    return socket.inet_pton(family, ip_addr)

def is_ipv4(ip: str) -> bool:
    """
    return true is ipv4, else false (ipv6)
    """
    return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)

def perform_thpt(client_ip:str, server_ip:str, do_upload:bool, pcap_filename:str) -> tuple[list]:
    """
    performs thpt analysis and reutrns the time and thpt variation

    this traverese the pkt file and reads line by line, the first number is the timestamp and the second byte has condensed information about the packet itself

    here we classify anything that has been sent out of the client to be an upload
    and anything that has been recieved by the client as download
    """
    if verbose: print(pcap_filename)
    cnt = 0
    bin_size = 1
    ipv4 = is_ipv4(client_ip)
    client_ip_bytes = get_bytes_from_ip(client_ip)
    server_ip_bytes = get_bytes_from_ip(server_ip)
    clock_thpt_dict = {}
    with open(pcap_filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # time_stamp is the time stamp wireshark notes the packet
        # buffered_data is in bytes
        # so at time time_stamp, NIC saw these buffer_data on the wire
        start_time_stamp = None
        for time_stamp, buffered_data in pcap:
            if start_time_stamp is None:
                start_time_stamp = time_stamp

            rel_time = int((time_stamp - start_time_stamp)//bin_size * bin_size)
            
            # initial assignment
            if rel_time not in clock_thpt_dict:
                clock_thpt_dict[rel_time] = 0
            
            
            eth = dpkt.ethernet.Ethernet(buffered_data)
            ip_data = eth.data
            
            if ipv4:
                if not isinstance(ip_data, dpkt.ip.IP):
                    continue
            else:
                if not isinstance(ip_data, dpkt.ip6.IP6):
                    continue
            
            dst = ip_data.dst
            src = ip_data.src

            tcp_data = ip_data.data 
            
            if not isinstance(tcp_data, dpkt.tcp.TCP): # may be udp, need to check
                continue

            # need to check all the uploads happening in the tcp connection created between the server and my computer
            if do_upload:
                if src==client_ip_bytes and dst==server_ip_bytes:
                    cnt += 1
                    clock_thpt_dict[rel_time] += len(tcp_data)
            # need to check all the uploads happening in the tcp connection created between the server and my computer
            else:
                # print(dst, client_ip_bytes)
                if dst==client_ip_bytes and src==server_ip_bytes: 
                    cnt += 1
                    clock_thpt_dict[rel_time] += len(tcp_data)

    if verbose: print(f"number of loads: {cnt}")
    bins = sorted(clock_thpt_dict.keys())
    values = [ (clock_thpt_dict[b] * 8) / (bin_size * 1e6) for b in bins ]  # kbps
    return list(bins), list(values)

def perform_rtt(client_ip:str, server_ip:str, do_upload:bool, pcap_filename:str) -> tuple[list]:
    """
    performs rtt analysis and return time and rtt variation
    """
    if verbose: print(f"working with: client_ip: {client_ip}, server_ip: {server_ip} and pcap_filename: {pcap_filename}")
    ipv4 = is_ipv4(client_ip)
    client_ip_bytes = get_bytes_from_ip(client_ip)
    server_ip_bytes = get_bytes_from_ip(server_ip)
    clock_rtt_dict = {}
    to_ack = {}
    with open(pcap_filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        start_time = None
        for time_stamp, buffered_data in pcap:
            if start_time is None:
                start_time = time_stamp
            
            rel_time = time_stamp - start_time

            if rel_time not in clock_rtt_dict:
                clock_rtt_dict[rel_time] = 0
            
            eth = dpkt.ethernet.Ethernet(buffered_data)

            if ipv4:
                if not isinstance(eth.data, dpkt.ip.IP): continue
            else:
                if not isinstance(eth.data, dpkt.ip6.IP6): continue
            
            ip_data = eth.data

            if not isinstance(ip_data.data, dpkt.tcp.TCP): continue

            tcp_data = ip_data.data

            src = ip_data.src
            dst = ip_data.dst
            
            if src==client_ip_bytes and dst==server_ip_bytes:
                key = tcp_data.seq + len(tcp_data.data)
                to_ack[key] = rel_time
                
            elif src==server_ip_bytes and dst==client_ip_bytes:
                key = tcp_data.ack
                if key in to_ack:
                    clock_rtt_dict[rel_time] = rel_time - to_ack[key]
    if verbose: print(f"number of rtts recorded: {len(clock_rtt_dict)}")
    return list(clock_rtt_dict.keys()), list(clock_rtt_dict.values())

def tcp_rtt_times(pcap_file: str):
    """
    Extract RTTs from TCP packets in a pcap.
    Returns (times, rtts) where:
        times = list of timestamps when RTT was measured
        rtts  = list of RTT values in milliseconds
    """

    sent_packets = {}   # (src, dst, sport, dport, seq) -> send_time
    rtts = []
    times = []

    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                tcp = ip.data

                # 4-tuple to uniquely identify flow
                flow = (ip.src, ip.dst, tcp.sport, tcp.dport)

                # If data is being sent (len > 0)
                if len(tcp.data) > 0:
                    seq = tcp.seq
                    # If already seen, it's a retransmission -> ignore
                    if (flow, seq) not in sent_packets:
                        sent_packets[(flow, seq)] = ts

                # If this is an ACK
                if (tcp.flags & dpkt.tcp.TH_ACK):
                    ack = tcp.ack
                    # Reverse flow (ACK comes back from other side)
                    rev_flow = (ip.dst, ip.src, tcp.dport, tcp.sport)

                    # Find if this ACK acknowledges any seq we sent
                    to_delete = []
                    for (f, seq), t_sent in sent_packets.items():
                        if f == rev_flow and seq < ack:
                            rtt = (ts - t_sent) * 1000.0  # ms
                            rtts.append(rtt)
                            times.append(ts)
                            to_delete.append((f, seq))

                    # cleanup acknowledged packets
                    for key in to_delete:
                        del sent_packets[key]

            except (dpkt.UnpackError, ValueError):
                continue

    return times, rtts

def plot(x: list[float], y: list[float], xlabel: str, ylabel: str, label: str, title: str, save_loc: str, window_start: float = 3.0, window_length:float=1e9) -> None:
    """
    General purpose plotter.
    """
    x_window, y_window = [], []
    for xi, yi in zip(x, y):
        if window_start <= xi < window_start + window_length:
            x_window.append(xi)
            y_window.append(yi)

    if x_window:
        plt.plot(x_window, y_window, marker="o", color="orange", label=f"{label}")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)

    if verbose: print(f"saving at {save_loc}")
    plt.tight_layout()
    plt.savefig(save_loc)
    plt.close()
 
def main():
    
    if verbose:
        print(f"""
            client_ip = {args.client}
            server_ip = {args.server}
            do_thpt = {args.throughput}
            do_upload = {args.up}
            do_download = {args.down}
            do_rtt = {args.rtt}
            version = {args.version}
            ipv6 = {args.safe}
            verbose = {args.verbose}
        """)

    if do_thpt:
        x, y =perform_thpt(client_ip, server_ip, do_upload, pcap_filename)
    
    else:
        x, y = perform_rtt(client_ip, server_ip, True, pcap_filename)


    if do_thpt:
        if do_upload:
            save_loc = f"up_throughput{"_s" if ipv6 else ""}{v}.png"
            title = f"Upload Throughput using 1 sec bins (http{"s" if ipv6 else ""})"
            ylabel = "Upload Throughput in Mbps"
            label = "Upload"
        else:
            save_loc = f"down_throughput{"_s" if ipv6 else ""}{v}.png"
            title = f"Download Throughput using 1 sec bins (http{"s" if ipv6 else ""})"
            ylabel = "Download Throughput in Mbps"
            label = "Download"
    if do_rtt:
        save_loc = f"rtt{"_s" if ipv6 else ""}{v}.png"
        title = f"RTT (http{"s" if ipv6 else ""})"
        ylabel = "RTT"
        label = "RTT"

    plot(x, y, "wall clock in sec", ylabel, label, title, save_loc, window_start=0.0, window_length=1e9)# if do_rtt else 1)

def submain():
    med = dns_query_response_times(pcap_filename)
    print(med)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parse an offline packet and identify stats")

    parser.add_argument("--client", type=str, help="client ip address")
    parser.add_argument("--server", type=str, help="server ip address")
    parser.add_argument("--throughput", action="store_true", help="calculate throughput")
    parser.add_argument("--rtt", action="store_true", help="calculate rtt")
    parser.add_argument("--up", action="store_true", help="perform uploads")
    parser.add_argument("--down", action="store_true", help="perform downloads")
    parser.add_argument("--file", type=str, help="pcap file name")
    parser.add_argument("--version", type=str, default="", help="enter verison")
    parser.add_argument("--safe", action="store_true", help="if https")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase verbosity")
    args = parser.parse_args()
    client_ip = args.client
    server_ip = args.server
    do_thpt = args.throughput
    do_upload = args.up
    do_download = args.down
    do_rtt = args.rtt
    pcap_filename = args.file
    v = args.version
    ipv6 = args.safe
    verbose = args.verbose
    main()
    # submain()