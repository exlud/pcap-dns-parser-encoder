#!/bin/sh

# actually I haven't seen any class other than IN, so...
sed -i 's/;I;/;/g' $1 

# A record for IPv4
sed -i 's/;4;/ A/g' $1

# AAAA record for IPv6
sed -i 's/;6;/ AAAA/g' $1

