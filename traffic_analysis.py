import dpkt
import socket
import matplotlib.pyplot as plt
from collections import defaultdict
import argparse

# ----------- CONFIG -------------
PCAP_FILE = "capture.pcap"
CLIENT_IP = "192.168.1.10"   # <-- replace with your machine's IP
WINDOW = 1.0                 # seconds (for throughput bins)
# --------------------------------

def inet_to_str(inet):
    """Convert inet object to a string IP address."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# Data containers
upload_bytes = defaultdict(int)
download_bytes = defaultdict(int)
uplink_rtts = defaultdict(list)

# TCP tracking for RTT
unacked = {}  # key=(src,dst,seq) → timestamp

with open(PCAP_FILE, "rb") as f:
    pcap = dpkt.pcap.Reader(f)
    start_ts = None
    
    for ts, buf in pcap:
        if start_ts is None:
            start_ts = ts
        rel_ts = ts - start_ts
        
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ip = eth.data
        src = inet_to_str(ip.src)
        dst = inet_to_str(ip.dst)
        
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        
        tcp = ip.data
        
        # Throughput classification (upload/download)
        window = int(rel_ts // WINDOW)
        if src == CLIENT_IP:
            upload_bytes[window] += len(tcp)
        elif dst == CLIENT_IP:
            download_bytes[window] += len(tcp)
        
        # RTT calculation (uplink)
        if src == CLIENT_IP:
            # Only consider data packets with payload
            if len(tcp.data) > 0:
                key = (dst, src, tcp.seq + len(tcp.data))
                unacked[key] = ts
        elif dst == CLIENT_IP:
            # This is an ACK coming back to client
            if tcp.ack:
                key = (src, dst, tcp.ack)
                if key in unacked:
                    rtt = ts - unacked[key]
                    uplink_rtts[window].append(rtt * 1000.0)  # in ms
                    del unacked[key]

# Convert throughput to Mbps
def dict_to_series(d):
    max_t = max(d.keys()) if d else 0
    return [ (d[t] * 8) / 1e6 for t in range(max_t+1) ]  # Mbps

upload_series = dict_to_series(upload_bytes)
download_series = dict_to_series(download_bytes)

# Plotting
plt.figure(figsize=(12, 8))

# Download throughput
plt.subplot(3, 1, 1)
plt.plot(download_series, label="Download")
plt.ylabel("Mbps")
plt.title("Download Throughput (1s window)")
plt.legend()

# Upload throughput
plt.subplot(3, 1, 2)
plt.plot(upload_series, label="Upload", color="orange")
plt.ylabel("Mbps")
plt.title("Upload Throughput (1s window)")
plt.legend()

# RTTs
plt.subplot(3, 1, 3)
rtt_times = []
rtt_vals = []
for t, vals in uplink_rtts.items():
    for v in vals:
        rtt_times.append(t)
        rtt_vals.append(v)
plt.scatter(rtt_times, rtt_vals, s=10, color="green")
plt.ylabel("RTT (ms)")
plt.xlabel("Time window (s)")
plt.title("Uplink RTTs (1s window)")

plt.tight_layout()
plt.show()


def perform_thpt(client_ip:str, server_ip:str, do_upload:bool) -> tuple[list]:
    """
    performs thpt analysis and reutrns the time and thpt variation
    """
    pass #TODO

def perform_rtt(client_ip:str, server_ip:str, do_upload:bool=True) -> tuple[list]:
    """
    performs rtt analysis and return time and rtt variation
    """
    pass # TODO

def plot(x:list[float], y:list[float], xlabel:str, ylable:str, title:str) -> None:
    """
    general purpose plotter 
    """
    pass # TODO

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parse an offline packet and identify stats")

    parser.add_argument("--client", type=str, help="client ip address")
    parser.add_argument("--server", type=str, help="server ip address")
    parser.add_argument("--throughput", action="store_true", help="calculate throughput")
    parser.add_argument("--rtt", action="store_true", help="calculate rtt")
    parser.add_argument("--up", action="store_true", help="perform uploads")
    parser.add_argument("--down", action="store_true", help="perform downloads")

    args = parser.parse_args()
    client_ip = args.client
    server_ip = args.server
    do_thpt = args.throughput
    do_upload = args.upload
    do_download = args.download
    do_rtt = args.rtt

    if do_thpt:
        x, y = perform_thpt(client_ip, server_ip, do_upload)
    
    else:
        x, y = perform_rtt(client_ip, server_ip, do_upload)

    plot(x, y)