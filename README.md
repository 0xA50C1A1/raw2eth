### What? 
A tiny tool that converts PCAP files of `DLT_RAW` and `DLT_IPV4`/`DLT_IPV6` (thanks to [Ivan Nardi](https://github.com/IvanNardi) for that) link-layer header type to `DLT_EN10MB` (Ethernet) by slapping on fake MAC addresses.

### Why? 
I needed to merge PCAPs from Wireshark and PCAPdroid, but `ndpiReader` choked on mixed DLT types. `editcap` and `tcprewrite` don't provide such feature, so I wrote this.

### Why C?
- I'm not good at Python.
- `libpcap` does the heavy lifting anyway.

### How?
1. Build it (requires `libpcap`):
   ```bash
   mkdir build && cd build
   cmake .. && make
   ```
2. Run it:
   ```bash
   ./raw2eth -i raw.pcap -o fake_eth.pcap
   ```
3. Profit.

### Where?
Tested on Linux. Might work on *BSD and macOS if you're lucky. 
