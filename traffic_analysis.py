import dpkt
import socket
import matplotlib.pyplot as plt
from collections import defaultdict
import argparse

# # ----------- CONFIG -------------
# pcap_filename = "capture.pcap"
# CLIENT_IP = "192.168.1.10"   # <-- replace with your machine's IP
# WINDOW = 1.0                 # seconds (for throughput bins)
# # --------------------------------

# def inet_to_str(inet):
#     """Convert inet object to a string IP address."""
#     try:
#         return socket.inet_ntop(socket.AF_INET, inet)
#     except ValueError:
#         return socket.inet_ntop(socket.AF_INET6, inet)

# # Data containers
# upload_bytes = defaultdict(int)
# download_bytes = defaultdict(int)
# uplink_rtts = defaultdict(list)

# # TCP tracking for RTT
# unacked = {}  # key=(src,dst,seq) → timestamp

# with open(pcap_filename, "rb") as f:
#     pcap = dpkt.pcap.Reader(f)
#     start_ts = None
    
#     for ts, buf in pcap:
#         if start_ts is None:
#             start_ts = ts
#         rel_ts = ts - start_ts
        
#         eth = dpkt.ethernet.Ethernet(buf)
#         if not isinstance(eth.data, dpkt.ip.IP):
#             continue
        
#         ip = eth.data
#         src = inet_to_str(ip.src)
#         dst = inet_to_str(ip.dst)
        
#         if not isinstance(ip.data, dpkt.tcp.TCP):
#             continue
        
#         tcp = ip.data
#         # Throughput classification (upload/download)
#         window = int(rel_ts // WINDOW)
#         if src == CLIENT_IP:
#             upload_bytes[window] += len(tcp)
#         elif dst == CLIENT_IP:
#             download_bytes[window] += len(tcp)
        
#         # RTT calculation (uplink)
#         if src == CLIENT_IP:
#             # Only consider data packets with payload
#             if len(tcp.data) > 0:
#                 key = (dst, src, tcp.seq + len(tcp.data))
#                 unacked[key] = ts
#         elif dst == CLIENT_IP:
#             # This is an ACK coming back to client
#             if tcp.ack:
#                 key = (src, dst, tcp.ack)
#                 if key in unacked:
#                     rtt = ts - unacked[key]
#                     uplink_rtts[window].append(rtt * 1000.0)  # in ms
#                     del unacked[key]

# # Convert throughput to Mbps
# def dict_to_series(d):
#     max_t = max(d.keys()) if d else 0
#     return [ (d[t] * 8) / 1e6 for t in range(max_t+1) ]  # Mbps

# upload_series = dict_to_series(upload_bytes)
# download_series = dict_to_series(download_bytes)

# # Plotting
# plt.figure(figsize=(12, 8))

# # Download throughput
# plt.subplot(3, 1, 1)
# plt.plot(download_series, label="Download")
# plt.ylabel("Mbps")
# plt.title("Download Throughput (1s window)")
# plt.legend()

# # Upload throughput
# plt.subplot(3, 1, 2)
# plt.plot(upload_series, label="Upload", color="orange")
# plt.ylabel("Mbps")
# plt.title("Upload Throughput (1s window)")
# plt.legend()

# # RTTs
# plt.subplot(3, 1, 3)
# rtt_times = []
# rtt_vals = []
# for t, vals in uplink_rtts.items():
#     for v in vals:
#         rtt_times.append(t)
#         rtt_vals.append(v)
# plt.scatter(rtt_times, rtt_vals, s=10, color="green")
# plt.ylabel("RTT (ms)")
# plt.xlabel("Time window (s)")
# plt.title("Uplink RTTs (1s window)")

# plt.tight_layout()
# plt.show()

def get_pcap_from_file(filename:str)-> any:
    """
    use it for loading information from pcap
    """
    with open(filename, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

    return pcap

def get_bytes_from_ip(ip_addr:str) -> bytes:
    """
    converter from ip address to bytes
    """

    return socket.inet_aton(ip_addr)


def perform_thpt(client_ip:str, server_ip:str, do_upload:bool, pcap_filename:str) -> tuple[list]:
    """
    performs thpt analysis and reutrns the time and thpt variation

    this traverese the pkt file and reads line by line, the first number is the timestamp and the second byte has condensed information about the packet itself

    here we classify anything that has been sent out of the client to be an upload
    and anything that has been recieved by the client as download
    """
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

            time_duration = time_stamp - start_time_stamp
            
            # initial assignment
            if time_duration not in clock_thpt_dict:
                clock_thpt_dict[time_duration] = 0
            
            
            eth = dpkt.ethernet.Ethernet(buffered_data)
            ip_data = eth.data
            
            if not isinstance(ip_data, dpkt.ip.IP):
                # print(f"skipping {time_duration}, ip mismatch")
                continue
            
            dst = ip_data.dst
            src = ip_data.src
            
            tcp_data = ip_data.data
            
            if not isinstance(tcp_data, dpkt.tcp.TCP):
                continue

            if do_upload:
                if src==client_ip_bytes and dst==server_ip_bytes: 
                    clock_thpt_dict[time_duration] += len(tcp_data)
            else:
                if src==server_ip_bytes and dst==client_ip_bytes: 
                    clock_thpt_dict[time_duration] += len(tcp_data)

    # print(clock_thpt_dict)
    return list(clock_thpt_dict.keys()), list(clock_thpt_dict.values())

def perform_rtt(client_ip:str, server_ip:str, do_upload:bool, pcap_filename:str) -> tuple[list]:
    """
    performs rtt analysis and return time and rtt variation
    """
    print(f"working with: client_ip: {client_ip}, server_ip: {server_ip} and pcap_filename: {pcap_filename}")
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

            if not isinstance(eth.data, dpkt.ip.IP): continue

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
                    print(clock_rtt_dict[time_duration])
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
        plt.plot(x_window, y_window, marker="o", color="orange", label=f"{label} (Zoom {window_start}-{window_start+1}s)")
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

    args = parser.parse_args()
    client_ip = args.client
    server_ip = args.server
    do_thpt = args.throughput
    do_upload = args.up
    do_download = args.down
    do_rtt = args.rtt
    pcap_filename = args.file

    print(f"""
        client_ip = {args.client}
        server_ip = {args.server}
        do_thpt = {args.throughput}
        do_upload = {args.up}
        do_download = {args.down}
        do_rtt = {args.rtt}
    """)

    if do_thpt:
        x, y =perform_thpt(client_ip, server_ip, do_upload, pcap_filename)
        y = [i * 8 for i in y] # for bits conversion from bytes
    
    else:
        x, y = perform_rtt(client_ip, server_ip, True, pcap_filename)

    # Plotting, can be made more effi
    is_s = pcap_filename.split(".")[0][-1]=="s"
    if do_thpt:
        if do_upload:
            save_loc = f"up_throughput{"_s" if is_s else ""}.png"
            title = f"Upload Throughput in 1 sec window (http{"s" if is_s else ""})"
            ylabel = "Upload Throughput"
            label = "Upload"
        else:
            save_loc = f"down_throughput{"_s" if is_s else ""}.png"
            title = f"Download Throughput in 1 sec window (http{"s" if is_s else ""})"
            ylabel = "Download Throughput"
            label = "Download"
    if do_rtt:
        save_loc = f"rtt{"_s" if is_s else ""}.png"
        title = f"RTT (http{"s" if is_s else ""})"
        ylabel = "RTT"
        label = "RTT"

    plot(x, y, "wall clock", ylabel, label, title, save_loc, window_start=0)