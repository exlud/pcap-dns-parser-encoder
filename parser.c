#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap/pcap.h>
#include "parser.h"

struct dnshdr {
  uint16_t tid;
  uint16_t flags;
  uint16_t questions;
  uint16_t answer_rrs;
  uint16_t authority_rrs;
  uint16_t additional_rrs;
};

#define dns_is_query(q)  ((ntohs((q)->flags) & 0x8000) == 0)
#define dns_is_truncated(q)  ((ntohs((q)->flags) & 0x0200) != 0)
#define dns_question_number(q)  (ntohs((q)->questions))

static int parse_questions_to_encoded_string(uint8_t * data, uint16_t len, uint16_t cnt);

int parser(const char * input, const char * output)
{
  int ret = 0;
  FILE * ofile;
  if(output == NULL) {
    ofile = stdout;
  } else {
    if((ofile = fopen(output, "w")) == NULL) {
      fprintf(stderr, "Can not write to file %s\n", output);
      return -EIO;
    }
  }

  char err[PCAP_ERRBUF_SIZE];
  pcap_t * pcap = pcap_open_offline(input, err);
  if(pcap == NULL) {
    fprintf(stderr, "Can not open file %s: %s\n", input, err);
    ret = -EIO;
    goto err1;
  }

  const uint8_t *packet;
  struct pcap_pkthdr hdr;
  while((packet = pcap_next(pcap, &hdr)) != NULL) {
    struct ethhdr * eth = (struct ethhdr *)packet;
    if(ntohs(eth->h_proto) != ETH_P_IP) // 802.1q not considered
      continue;

    struct iphdr * ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    if(ip->protocol != IPPROTO_UDP)
      continue;

    struct udphdr * udp = (struct udphdr *)((uint8_t *)ip + ip->ihl*4);
    if(ntohs(udp->dest) != 53) // 53 default DNS query destination port
      continue;

    struct dnshdr * dns = (struct dnshdr *)((uint8_t *)udp + sizeof(struct udphdr));

    if(!dns_is_query(dns)) // ignore dns response
      continue;

    if(dns_is_truncated(dns)) // truncated dns message ignored
      continue;

    uint8_t * payload = (uint8_t *)dns + sizeof(struct dnshdr);
    // dns payload length = udp length - udp header - dns header
    uint16_t plen = ntohs(udp->len) - sizeof(struct udphdr) - sizeof(struct dnshdr);
    uint16_t cnt = dns_question_number(dns);

    uint8_t * data = (uint8_t *)calloc(plen + 1, sizeof(uint8_t));
    memcpy(data, payload, plen);
    if(parse_questions_to_encoded_string(data, plen, cnt) == -1) {
      fprintf(stderr, "Parse questions failed\n");
      ret = -1;
      free(data);
      goto err;
    }

    fprintf(ofile, "%ld.%06ld\n", hdr.ts.tv_sec, hdr.ts.tv_usec);
    fprintf(ofile, "%s\n", data + 1);
    fprintf(ofile, "\n");
    free(data);
  }

err:
  pcap_close(pcap);
err1:
  if(ofile != stderr)
    fclose(ofile);
  return ret;
}

// example: a.fi + bc.fi, AAAA type(00 1c), A type(00 01), IN class(00 01) 
// ascii:     a     f  i                    b  c     f  i
// hex:    01 61 02 66 69 00 00 1c 00 01 02 62 63 02 66 69 00 00 01 00 01
// s1:     ^ label length
// s2:           ^ move to the next label
// s3:                    ^ end label
// s4:                       ^  ^  ^  ^ four octets
// s5:                                   ^ next question
//
// output in string:
//         .a.fi;6;I;.bc.fi;4;I;
// need further postprocess by script: (not here)
//          a.fi AAAA bc.fi A
//
// Note:
// not support message compression defined in RFC1035 section 4.1.4
static int parse_questions_to_encoded_string(uint8_t * data, uint16_t len, uint16_t cnt)
{
  uint16_t found = 0;
  for(uint8_t i = 0; i < len - 4;) {
    if(data[i] != 0) {
      uint8_t label_length = data[i];
      data[i] = '.';
      i += (label_length + 1);
    } else {
      found++;
      data[i] = ';';
      
      // type '4' for A record, '6' for AAAA record, '?' for others
      if(data[i+2] == 1) {
        data[i+1] = '4';
      } else if(data[i+2] == 28){
        data[i+1] = '6';
      } else {
        data[i+1] = '?';
      }
      data[i+2] = ';';

      // class 'I' for IN, '?' for others
      if(data[i+4] == 1)
      	data[i+3] = 'I';
      else
        data[i+3] = '?';
      data[i+4] = ';';
      if(found == cnt)
       break;
      i+=5;
    }
  }

  if(found != cnt) {
    fprintf(stderr, "Error: expect %d records, found %d\n", cnt, found);
    return -1;
  }
  return 0;
}
