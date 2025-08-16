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

## ICMP Protocol 
- IP (internet protocol) used for host to host interconnection in a system of networks, specifically called "catenet"
- Network connecting devices are called gateways
- Gateways communicate using Gateway to Gateway protocol
- gateway or destination host communicates with a source host (occasionaly) using ICMP, eg. report error in processsing a datagram
- ICMP > IP
- ICMP control messages/ emergency messages