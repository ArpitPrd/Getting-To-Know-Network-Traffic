## To Learn

- ping (doc): https://www.ibm.com/docs/en/aix/7.2.0?topic=p-ping-command
- traceroute (doc): https://www.ibm.com/docs/sl/aix/7.1.0?topic=t-traceroute-command
- Autonomous System (wiki): https://en.wikipedia.org/wiki/Autonomous_system_(Internet)
- dns: https://www.cloudflare.com/learning/dns/what-is-dns/

- Also learn how to use latex within VS Code to allow git support

## Ping

- link: https://linux.die.net/man/8/ping
- uses ICMP Protocol 
- IP header without package is 20 bytes
- -a does some audible ping
- so you get stats of ping, you continuously keep pinging a website 
- stats from ping www.google.com
    - 0% loss
    - time 9013ms
    - avg 8.288ms

- stats from craigslist.com
- GFG:
    - full form Packet INternet Grouper
    - tests the operationality of the destination computer
    - ping used with an operating system that supports networking (cannot access the networking system without OS)
    - network designers use this to diagonase networks. A useful post-deplotment feature, helps debug the network
    - ICMP Echo Request, echo because it sends back the same data
    - Ping uses = ICMP Echo Request + response messages
    - If active responds with ICMP reply packet
    - RTT = Round Trip Time
    - speed tests
    - for low bandwidth data like playing songs 
    - for high bandwodth data like dowloading a video
    - idea - bandwidth is mbps, speed is RTT, depending upon application one might select one for the other
    - for streaming purposes we require RTT to be high, but downloading we require bandwidth to be high
    - the relay may be delayed because of lager routes to the nearest server

- ping command can be very hard on a network and must be used with caution
- 8 header bytes for ICMP

## ICMP Protocol 
- IP (internet protocol) used for host to host interconnection in a system of networks, specifically called "catenet"
- Network connecting devices are called gateways
- Gateways communicate using Gateway to Gateway protocol
- gateway or destination host communicates with a source host (occasionaly) using ICMP, eg. report error in processsing a datagram
- ICMP > IP
- ICMP control messages/ emergency messages

## IP

- differ on address spaces 4, 6
- IPv6 have alpha numeric IP addresses
- TLD - top level domain server, first rack of the library: com, in, etc
- the first ocetet - assigns the big coorpation IP Spaces
- the second octet - assigns the Internet Service Provider
- the third octet - assigns the sub network services
- the fourth octet - modem ot the cable for transportation
- State.City.Street.House#
- network id (same if the same internet is used) + host id
- these two parts may not be split equally, 1,2,3 may be network id and 4 may be host id
- Anymous IPs for VPN and stuff, if you access through vpn,it can be avoided. malicouhs acts cannot be detected
- Loopback IP Address, used for communicating within a computer machine, doesnt pass packets to NIC, and only interactes with OS, we have reserverd ip address loopback with 127.0.0.0 around these numbers
- these request move up and down inside the stack and do not go out of the computer (invariant to this ip address)
- so when you want to communicate or ssh, do not use this loopback address (ig)
- 10, 142, 192, 172, 
- so you have these group people who set standards to IP and the Internet 
- get geo location from: https://www.maxmind.com/en/geoip-web-services-demo


## traceroute

- ttl = time to live: self destruction message
- hack of using ttl again and again to find the route assumed on the travel: www.varonis.com/blog/what-is-traceroute
- An autonomous system (AS) is a collection of connected Internet Protocol (IP) routing prefixes under the control of one or more network operators on behalf of a single administrative entity or domain, that presents a common and clearly defined routing policy to the Internet

## General Pointers

- xargs can be used to map the output from the prev commands to the input of the current command
- awk '{print $z}' prints a particular column space separated 
- sed '1d' drops the first row 
- there are undersea cables
- find the asn from whois -h whois.cymru.com " -v 172.217.26.36"
- DHCP is intended for information availability for the client to have all informaation about the servers
- wak return exit status
- int.to_bytes(): https://docs.python.org/3/library/stdtypes.html (search bytes for more operation)
- int.bit_count(): number of ones
- int.from_bytes()
- ethernet is also the source through which we can get the wifi analysis in libpcap
- difference is that ethernet is cabled and wifi is not cabled
- sudo apt net-tools for all the network tools such as ipconfig, ifconf
- \- is converted to _ in parser.parse_args().<can use _ here>
- chatgpt blends with convos, but google searches are rigid

## Submission

- python traffic_analysis.py --file <filename.pcap> --client --server --throughput --up
- ip address for http://www.httpvshttps.com/: 45.33.7.16
- for https://www.httpvshttps.com/: 45.33.7.16, 151.101.208.157, 2404:6800:4003:c0f::9c, 2600:3c00::f03c:91ff:fe28:3acc
- my ip: 10.184.13.134, 2001:df4:e000:3fd1::b3ab
- they are the same because http is an application level protocol and is does not affect the dns lookup, becuase what matters is the domain name, that establishes connection in the link layer, which is determined by the last three words in domain. what protocol is being used does not change the server, hence the ip
- before submitting make sure to remove the hack to identify s

- need to check the slight peek in upload?

## DNS

- this is like the phone book system
- DNS Servers have caching systems
- reverse DNS look up is identifying the DNS from the ip address of a server
- forward dns look up dns name to ip address
- geo location is airport location\
- why are there more than three domains hosted on the same IP Address
- dns is round robin, for load balancing, so there may be different Domain Names for the same IP Address
- for load balancing ip can share it self 
- dns lookups from here: https://www.nslookup.io/website-to-ip-lookup/
- to clear dns cache use: about:networking#dns

## Wireshark

- is only a measurement tool 
- cannot detect suspicious activity directly to the eye, but can use it for analysis purposes
- it cannot send out or disrupt/corrupt data
- if the machine supports some mem management and security management, then wiresharks can mostly be used on them.
- compulsory: 500 MB RAM and 500MB Disk space, just in case caputures are pretty high
- the length capture (idt can be limited by a mere human) depends on the amount of trafiic that you are surrounded with. For more traffic wireshark demands for more amount of space
- doc for wireshar: https://www.wireshark.org/docs/wsug_html_chunked/ChIntroDownload.html
- eth0 for ethernet as a medium and wlan0 for wifi

- websites to visit: http://www.httpvshttps.com
    - clear browser and dns cache before starting out
    - type in the browser: about:networking#dns

- tcpdump: https://medium.com/@packetnaut/deeper-dive-dns-query-and-response-with-wireshark-and-tcpdump-with-hex-offsets-f30a2046779f
- $-l$ for output line buffer, for ease of transfer to the other commands (flush)
- UDP is another protocol like TCP
- wireshark can display name only related to the DNS protocol
- this is the wifi interface:wlxdc627966b656
- mentions the port to port transfer
- wireshark denotes everything that happens on the interface
- can caputure from different types of network hardware
- can capture from more than one interface simulatanroulsy
- can capture from USB also (amazing)
- underlging software is dumpcap
- dumpcap --interface wlxcd... -F pcap -w http.pcap
- capinfo may be used for filtering data
- capinfo <file> -i for kbps of data (more infor here:https://www.wireshark.org/docs/wsug_html_chunked/AppToolscapinfos.html)

## User Datagram Protocol 

- Used to transfer data in high speed
- tco does a handshake before establishing connectin
- udp directly starts sending out data
- udp does not check the proper arrival of the data, tcp does
- it is very linient in every terms, can use for high speed data transfer at limited capacity of wire (data reate)
- if udp datagram is lost in the transit, the reciever would not no it
- spotify works over udp, becauuse small data transfers are ok for them

## TCP

- in a single TCP connections you have multiple http connections
- udp and tcp are transferring things, whereas http 
- tcp manages the big connections
HTTP (Application Layer)    HTTP (Application Layer)
         |                              |
        TCP -------------------------- TCP 
           (this establishes connection)
- so you build a port throigh which you can make transfers
- the assurance of having data reliability loosens the constraint of programmer having to write data transfer codes (or any such relibility codes or communication safeguard softwares) whatsoever
- TCP can tranfer continuous 8 bit octets in both direcctions by packaging some number of bytes into segs for transmission across the internet system
- in general TCP decides when to block and allow packets in its own convienice
- TCP must be able to recover data that is lost, duplicated, damaged, out of order by the internet.
- Handles all this by attaching numbers to packets and recieving ACK from reciever.
- if ACK is not recieved in the time out interval, the data is retransmitted
- TCP time-out value is determined dynamically for each system, based on its round trip times
- the sequence numbers may be used order the packets and eliminate dups
- Checksum, ensures no damage, by checking them at the reciever and sending RETRANMSIT signal 
- TCP send the window with ACK, to communicate the range of acceptable sequence. This indicates the Sender the allowed number of octets that the sender might send until further NOTICE
- TCP must initialise and maintain a certain status information 
- a connection = status information + sockets + sequence numbers + window sizes
- each connection uniquly identified by a pair of sockets on each side
- we may specify the TCP with security and precendence information 
- sequence number keeps track of every byte sent out of the host
- acknowlwdmwnt number is a track for every byte that has been recvcieved 
- the local hosts sequence number usually matches the remote hosts ack number
- local hosts ack number usually matches the remote hosts sequenne number
- may contain ranges indicating the start and the end byte. Ack contains informaation for the next packet

seq 1000
ack 1000


seq 1000
ack 1000

- if running on the same IP Address, the port directs the information to a specific application program
- httpvshttps runs on the same ip address, once data encapsulation is recieved from the lower levels this sent out the application layer by checking the port if it is 80 sends to HTTP other wise 430 then HTTPS
- adheres to the fact of keeping the network to be dumb and end hosts to be smart
- retransmissions can be found, if wither A != S + L
- TCP sends out updated ack num

## wrt to assignment queries:

- reponse request = udp.stream==0
- number of http request = http.request


## Issues faced

- pcapng is not supported by libpcap, convert it to pcap either by using save-as, or follow this link: https://stackoverflow.com/questions/23523524/dpkt-invalid-tcpdump-header-error


## dpkt

- Use this to learn about dpkt.pcap: https://dpkt.readthedocs.io/en/latest/api/api_auto.html#module-dpkt.pcap
- reads all the packets, and stores them in some format, you may iterate over them, check traffic_analysis.py
- wireshark converts the image to used by other softwares, they may use this over and agin 
- pcap is one such file that can be operated upon by libpcap, pcap is a generally accepted format (protocol) of storing the way things are supposed to be stored
- there is some magic number on the top of pcap files, maybe to get protocol
- have to use ip to address the src and dst
- ip data -> tcp data 
- eth.src provides the mac address of the computer. 6bytes. 6bytes addressing mostly it is the mac address of the computer
- data has been buffered in the file, and can be used for information extraction about almost everything, including ethernet information, tcp informaiton, udp information and everything else.

- IP was derieved from the dpkt.Packet, so this some sort of modelling of the packet along with additional information, that includes information such as the soucre ip, dest ip.
- you can also pack and unpack, the packet to remove the header notifs

- also implemets various other checkers, like checksum, overflows, etc.. (can check myenv/lib/python3.12/site-packages/dpkt/dpkt.py)

- found something called vlan, which is virtual LAN, used for logical assignemnt of network devices centrally controlled by a switch

- this is a packet with more hanging informaiton dpkt.ip.IP

- DNS resolution is done using UDP
- Data Tramnsfer (more secire) done using TCP

- ehternet class captures the hardware aspects
- ip class captures the IP rules
- tcp class captures the tcp rules
- dpkt is very less documented
- reader is a dump, packet data length of each record 
- ts, buf this is the length of the record
- use the dpkt class to have the buf parsed into more freinfly python objects sort of technique, which is dpkt.ethernet.Ethernet in this case only, you may find other according to requirement
- eth decodes both IP and TCP layer information as well, parses higher layer protocols
- when printed:
Ethernet(src='\x00\x1a\xa0kUf' (MAC), dst='\x00\x13I\xae\x84,' (MAC), data=IP(src='\xc0\xa8\n\n', off=16384, dst='C\x17\x030', sum=25129, len=52, p=6, id=51105, data=TCP(seq=9632694, off_x2=128, ack=3382015884, win=54, sum=65372, flags=17, dport=80, sport=56145)))
- src: Source MAC address
- dst: destination MAC Address
- data: Encapsulated in IP Object


IP(src='\xc0\xa8\n\n', off=16384, dst='C\x17\x030', sum=25129, len=52, p=6, id=51105, data=TCP(seq=9632694, off_x2=128, ack=3382015884, win=54, sum=65372, flags=17, dport=80, sport=56145))
- src: source IP Address
- dst: destination IP Address
- len: length of the packet
- p: (not sure)
- id: unique identification of the packet, during the conversation
- data: Encapsulated TCP message

TCP(seq=9632694, off_x2=128, ack=3382015884, win=54, sum=65372, flags=17, dport=80, sport=56145)
- seq: specifies the sequence number of the first byte of data
- off_x2: specifies the off set of the data portion in the segment
- ack: Identiffies the portion of the highest block recieved 
- win: specifies the amount of data the destination is willing to recieve
- sum: checksum, verifying the intergrity of the packet
- flags: Identify the segments valid
- dport: destination port of TCP Header, identifies port in the Application Program
- sport: source port of TCP Header, remmemeber that this was header, identifies port in the source Application Program

- Ethernet class has this speacial property, of having parsed the data of higher levels of the protocol stack. This actually quite useful. All of this is obtained from the read buffer
- Ethernet class, by the name atleast seems to be philosihically designed for the needs to understand the hardware.
- As information passes through the layers, we can keep peeling of the higher encapsulations: Peel Ethernet you get IP, peel IP you get TCP. Very nice encapsulations. Eventually it is just the data, and is used by the Application Layer
- For RTT calculation, associate the acknowledgment with the data packet whose sequence number S satisfies: A = S + L, where A is the acknowledgment number and L is the size (in bytes) of the data packet
3382015884 = 9632694 + 