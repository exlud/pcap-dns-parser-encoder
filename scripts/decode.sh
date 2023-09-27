#!/bin/sh
# 
# remove the 'I' code in the end of lines
# substitute '4' with 'A'
# substitute '6' with 'AAAA'

# example
# input
#     1695634014.737794
#     lh3.googleusercontent.com;6;I;
#
# output
#     1695634014.737794
#     lh3.googleusercontent.com AAAA


# actually I haven't seen any class other than IN, so...
sed -i 's/;I;/;/g' $1 

# A record for IPv4
sed -i 's/;4;/ A/g' $1

# AAAA record for IPv6
sed -i 's/;6;/ AAAA/g' $1

