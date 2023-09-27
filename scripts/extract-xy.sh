#!/bin/sh
# extract all timestamps as the x axis
# extract query host name as the y axis
#
# example
# input
#     1695634014.696863
#     clients1.google.com AAAA
#
#     1695634014.737772
#     lh3.googleusercontent.com A
#
#     1695634014.737794
#     lh3.googleusercontent.com AAAA
#
# output
# filename.x
#     1695634014.696863
#     1695634014.737772
#     1695634014.737794
# filename.y
#     clients1.google.com AAAA
#     lh3.googleusercontent.com A
#     lh3.googleusercontent.com AAAA
#

grep -E '^[0-9]+.[0-9]+$' $1 > $1.x
grep -v -E -e '^[0-9]+.[0-9]+$' -e '^$' $1 > $1.y
