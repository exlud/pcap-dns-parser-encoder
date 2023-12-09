# pcap-dns-parser-encoder
Parse offline pcap file, extract DNS query, estimate conditional probability. 
Then use the probability to explore the DNS sequence, which is the knowledge for prediction.

# dependency
libpcap-dev
```shell
apt install libpcap-dev
```

# use 
```shell
make
cp <your packets> packet-samples
./demo > result.txt
```
then you can get sequences like
```shell
  www.bing.com
  r.bing.com
  th.bing.com
  login.microsoftonline.com
```
which means `www.bing.com` as a DNS query, **maybe** sufficiently causes other queries.

# packet source
a submodule to fetch packet samples, currently it uses private repo of mine, due to privacy issue.
