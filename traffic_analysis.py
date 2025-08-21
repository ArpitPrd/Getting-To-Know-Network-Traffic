import dpkt
import socket
import matplotlib.pyplot as plt
from collections import defaultdict
import argparse
import ipaddress


def get_pcap_from_file(filename:str)-> any:
    """
    use it for loading information from pcap
    """
    with open(filename, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

    return pcap

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
    print(pcap_filename)
    bin_size = 0.5
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

            time_duration = int((time_stamp - start_time_stamp)//bin_size * bin_size)
            
            # initial assignment
            if time_duration not in clock_thpt_dict:
                clock_thpt_dict[time_duration] = 0
            
            
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
            if (not is_ipv4(src)):
                print("ipv6")
            tcp_data = ip_data.data 
            
            if not isinstance(tcp_data, dpkt.tcp.TCP): # may be udp, need to check
                continue
            
            # filters server traffic
            if src!=server_ip_bytes and dst!=server_ip_bytes: 
                # print(src, server_ip_bytes)
                continue

            # need to check all the uploads happening in the tcp connection created between the server and my computer
            if do_upload:
                if src==client_ip_bytes:
                    clock_thpt_dict[time_duration] += len(tcp_data)
                    print(f"update:{clock_thpt_dict[time_duration]}")
            # need to check all the uploads happening in the tcp connection created between the server and my computer
            else:
                if dst==client_ip_bytes: 
                    clock_thpt_dict[time_duration] += len(tcp_data)

    # print(clock_thpt_dict)
    bins = sorted(clock_thpt_dict.keys())
    values = [ (clock_thpt_dict[b] * 8) / (bin_size * 1e3) for b in bins ]  # kbps
    return list(bins), list(values)

def perform_rtt(client_ip:str, server_ip:str, do_upload:bool, pcap_filename:str) -> tuple[list]:
    """
    performs rtt analysis and return time and rtt variation
    """
    print(f"working with: client_ip: {client_ip}, server_ip: {server_ip} and pcap_filename: {pcap_filename}")
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
            
            time_duration = time_stamp - start_time

            if time_duration not in clock_rtt_dict:
                clock_rtt_dict[time_duration] = 0
            
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
                to_ack[key] = time_duration
                
            elif src==server_ip_bytes and dst==client_ip_bytes:
                key = tcp_data.ack
                if key in to_ack:
                    clock_rtt_dict[time_duration] = time_duration - to_ack[key]
    print(f"number of rtts recorded: {len(clock_rtt_dict)}")
    return list(clock_rtt_dict.keys()), list(clock_rtt_dict.values())


def plot(x: list[float], y: list[float], xlabel: str, ylabel: str, label: str, title: str, save_loc: str, window_start: float = 3.0, window_length:float=1e9) -> None:
    """
    General purpose plotter.
    Adds a subplot zoomed into a 1-second window [window_start, window_start+1).
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

    print(f"saving at {save_loc}")
    plt.tight_layout()
    plt.savefig(save_loc)
    plt.close()
 

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
    args = parser.parse_args()
    client_ip = args.client
    server_ip = args.server
    do_thpt = args.throughput
    do_upload = args.up
    do_download = args.down
    do_rtt = args.rtt
    pcap_filename = args.file
    v = args.version
    print(f"""
        client_ip = {args.client}
        server_ip = {args.server}
        do_thpt = {args.throughput}
        do_upload = {args.up}
        do_download = {args.down}
        do_rtt = {args.rtt}
        version = {args.version}
    """)

    if do_thpt:
        x, y =perform_thpt(client_ip, server_ip, do_upload, pcap_filename)
        y = [i * 8 for i in y] # for bits conversion from bytes
    
    else:
        x, y = perform_rtt(client_ip, server_ip, True, pcap_filename)

    # Plotting, can be made more effi
    is_s = False
    for l in pcap_filename: 
        if l=="s": is_s = True

    if do_thpt:
        if do_upload:
            save_loc = f"up_throughput{"_s" if is_s else ""}{v}.png"
            title = f"Upload Throughput in 1 sec window (http{"s" if is_s else ""})"
            ylabel = "Upload Throughput in bits per sec"
            label = "Upload"
        else:
            save_loc = f"down_throughput{"_s" if is_s else ""}{v}.png"
            title = f"Download Throughput in 1 sec window (http{"s" if is_s else ""})"
            ylabel = "Download Throughput in bits per sec"
            label = "Download"
    if do_rtt:
        save_loc = f"rtt{"_s" if is_s else ""}{v}.png"
        title = f"RTT (http{"s" if is_s else ""})"
        ylabel = "RTT"
        label = "RTT"

    plot(x, y, "wall clock", ylabel, label, title, save_loc, window_start=0.0, window_length=1e9)# if do_rtt else 1)