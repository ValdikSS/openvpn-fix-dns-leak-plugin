## OpenVPN plugin to fix Windows DNS Leaks
Windows 10 DNS resolver sends DNS requests in parallel to all available network interfaces and uses the fastest reply to come. If you use DNS from the local network, this problem allows your ISP or a hacker with Wi-Fi ap to hijack your DNS records and steal your data even if you use VPN .

This plugin should fix this issue for Windows 8.1 and Windows 10 users. [Read More](https://medium.com/@ValdikSS/beware-of-windows-10-dns-resolver-and-dns-leaks-5bc5bfb4e3f1).

### How to use
1. Download `fix-dns-leak-32.dll` for 32 bit system or `fix-dns-leak-64.dll` for 64 bit system
2. Add the following line to your OpenVPN configuration file:  
`plugin fix-dns-leak-32.dll`  
for 32 bit system or  
`plugin fix-dns-leak-64.dll`  
for 64 bit system

### How it works
This plugin implements Windows Filtering Platform userspace filter to block all IPv4 and IPv6 DNS queries from DNS Client service to port 53 except on OpenVPN's TAP interface. It works like a temporary firewall which clears its rules upon termination or crash. This is important as you won't get broken internet connection if OpenVPN client suddenly crashes, unlike with other methods.
