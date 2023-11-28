#!/bin/sh
tcpdump udp port 53 -s0 -C 1 -W 1 -w lud.pcap -Z lucius
