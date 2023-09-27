# pcap-dns-parser-encoder
Parse offline pcap file, extract DNS query in a custom encode format
Then use the post-process script to "decode", and extract timestamp for GNU octave

# dependency
libpcap-dev
```shell
apt install libpcap-dev
```

# example
```shell
make
./parser -f sample.pcap -o dns.txt
source post-process.sh dns.txt
```
one fragment in the output file
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

# packet source
a submodule to fetch packet samples, but only for my personal use.
samples are captured on my own PC, or shared by my classmates.
can not be public due to privacy issue.
