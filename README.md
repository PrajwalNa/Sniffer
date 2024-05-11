# Packet Sniffer

This is a simple packet sniffer written in C. It listens for packets on a network interface and displays information about each packet it captures.

## Features

- Captures TCP, UDP, ICMP, ARP, and other IP and Ethernet packets.
- Can be run in verbose mode to print detailed information about each packet.
- Can be run in promiscuous mode to capture all packets on the network, not just those destined for the host machine.

## Usage

Compile the program using a C compiler, then run the resulting executable. The program will start listening for packets and display a count of each type of packet it captures.

Press Ctrl+C to stop the program.

## Example

```bash
gcc main.c modules.c -o sniffer
./sniffer -h
```

# Note

This program requires root privileges to run, as it needs to access the raw network interface.

# Disclaimer

This tool is for educational purposes only. Use it responsibly and do not use it for illegal activities.
