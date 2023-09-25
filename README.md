# pcap-dns-parser-encoder
Parse offline pcap file, extract DNS query in a custom format

# example
```shell
make
./parser -f sample.pcap -o dns.txt
source post-process.sh dns.txt
```
one segment from the output file
```code
1695634014.531325
www.google.com A

1695634014.531335
www.google.com AAAA

1695634014.696850
clients1.google.com A

1695634014.696863
clients1.google.com AAAA

1695634014.737772
lh3.googleusercontent.com A

1695634014.737794
lh3.googleusercontent.com AAAA

1695634014.739364
fonts.googleapis.com A

1695634014.739390
fonts.googleapis.com AAAA
```
