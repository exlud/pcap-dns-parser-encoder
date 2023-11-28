#include <stdio.h>
#include <pcap/pcap.h>
#include "../protocol/dns.h"

int main(int argc, char * argv[])
{
  char err[PCAP_ERRBUF_SIZE];
  const char * input = "protocol_smoke_test.pcap";
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
  while((packet = pcap_next(pcap, &hdr)) != NULL) {
    struct question q;
    if(dns_parse(packet, &q) == 0) {
      msgnr++;
      if(q.query) {
        qrynr++;
      } else {
        respnr++;
      }

      if(q.query && q.type == 1)
        tid = q.tid;
	snprintf(name, 512, "%s", q.name);
    }
  }

  pcap_close(pcap);

  printf("\n");
  printf("Expect:\n");
  printf("dns:1064  query:1064  response:0\n");
  printf("last record: 001472 prg.smartadserver.com\n");
  printf("\n");
  printf("\n");
  printf("Result:\n");
  printf("dns:%04d  query:%04d  response:%d\n", msgnr, qrynr, respnr);
  printf("last record: %06d %s\n", tid, name);
  printf("\n");
err1:
  return 0;
}
