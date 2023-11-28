#include <string>
#include <tuple>
#include <stdio.h>
#include <pcap/pcap.h>
#include "protocol/dns.h"
#include "collector/collector.h"
#include "learner/learner.h"

int main(int argc, char * argv[])
{
  dns::learner learner;

  char err[PCAP_ERRBUF_SIZE];
  const char * input = "./packet-samples/example.pcap";
  pcap_t * pcap = pcap_open_offline(input, err);
  if(pcap == NULL) {
    fprintf(stderr, "Can not open file %s: %s\n", input, err);
    return -1;
  }

  int msgnr = 0, qrynr = 0, respnr = 0;
  char name[512] = {0};
  int tid = -1;

  const uint8_t *packet;
  struct pcap_pkthdr hdr;
  dns::collector collector;
  while((packet = pcap_next(pcap, &hdr)) != NULL) {
    struct question q;
    if(dns_parse(packet, &q) == 0) {
      if(q.query && q.type == DNS_TYPE_A) {
        collector.collect(std::make_tuple(hdr.ts.tv_sec, q.tid, true, std::string(q.name)));
      } else {
        collector.collect(std::make_tuple(hdr.ts.tv_sec, q.tid, false, std::string("")));
      }
    }
  }

  pcap_close(pcap);

  collector.grouping(2);
  collector.causing();
  
  for(auto m : collector._causals) {
    learner.feed(m);
  }
  for(auto m : collector._causals) {
    learner.feed(m);
  }
  learner.summary(); 

  return 0;
}
