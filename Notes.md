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

## Submission

- python traffic_analysis.py --file <filename.pcap> --client --server --throughput --up
- my ip
- ip address for http://www.httpvshttps.com/: 45.33.7.16
- for https://www.httpvshttps.com/: 45.33.7.16, 35.199.147.118
- my ip: 10.184.4.205
- they are the same because http is an application level protocol and is does not affect the dns lookup, becuase what matters is the domain name, that establishes connection in the link layer, which is determined by the last three words in domain. what protocol is being used does not change the server, hence the ip

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