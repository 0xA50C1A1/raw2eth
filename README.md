### What? 
A tiny tool that converts PCAP files of `DLT_RAW` and `DLT_IPV4`/`DLT_IPV6` (thanks to [Ivan Nardi](https://github.com/IvanNardi) for that) link-layer header type to `DLT_EN10MB` (Ethernet) by slapping on fake MAC addresses.

### Why? 
I needed to merge PCAPs from Wireshark and PCAPdroid, but `ndpiReader` choked on mixed link-layer header types. Yes, `tcprewrite --dlt=enet` exists. No, it doesn't work when you need it most 
(with mixed traffic), so I wrote this. Well, converting everything to `DLT_RAW` would be easier - but where's the fun in that?

### How?
0. Install dependencies:

   ```bash
   # Debian/Ubuntu
   sudo apt-get install cmake libpcap-dev
   # RHEL/CentOS/AlmaLinux
   sudo dnf install cmake libpcap-devel
   ```
1. Build it:

   ```bash
   mkdir build && cd build
   cmake .. && make
   ```
2. Run it:

   ```bash
   ./raw2eth -i raw.pcap -o fake_eth.pcap
   ```
3. Profit.

### Caveats & Notes

1. MAC Address Handling:
   - By default generates random locally-administered MACs (`02:xx:xx:xx:xx:xx`)
   - Use `-s`/`-d` to specify custom MACs (both must be provided)
   - No MAC preservation - all packets get the same addresses

2. Why C?
   - I'm not good at Python.
   - `libpcap` does the heavy lifting anyway.

3. Platform support
   - Tested on Linux. Might work on *BSD and macOS if you're lucky.
