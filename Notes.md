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

## Submission

- python traffic_analysis.py --file <filename.pcap> --client --server --throughput --up

## DNS

- this is like the phone book system
- DNS Servers have caching systems
- reverse DNS look up is identifying the DNS from the ip address of a server
- forward dns look up dns name to ip address
- geo location is airport location\
- why are there more than three domains hosted on the same IP Address
- dns is round robin, for load balancing, so there may be different Domain Names for the same IP Address
- for load balancing ip can share it self 