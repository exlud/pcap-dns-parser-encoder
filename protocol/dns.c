#include <asm/byteorder.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "dns.h"
#include "list.h"

// dns udp header as in rfc1035 4.1.1
struct dnshdr {
  uint16_t id; //transaction id
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint16_t rd:1, //query 0, response 1
	   tc:1, //truncation
	   aa:1, //authoritative answer
	   opcode:4, //standar query 0, inverse query 1, server status request 2
	   qr:1, //recursion desired
	   rcode:4, //response code, 0 for no error
	   z:3, //zero
	   ra:1; //recursion available
#elif defined(__BIG_ENDIAN_BITFIELD)
  uint16_t qr:1, //query 0, response 1
	   opcode:4, //standar query 0, inverse query 1, server status request 2
	   aa:1, //authoritative answer
	   tc:1, //truncation
	   rd:1, //recursion desired
	   ra:1, //recursion available
	   z:3, //zero
	   rcode:4; //response code, 0 for no error
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
  uint16_t qdcount; //number of questions
  uint16_t ancount; //number of answers
  uint16_t nscount; //number of authority records
  uint16_t arcount; //number of additional records
};

// rfc1035 4.1.1, 4.1.2
// not interested in resource records
struct dnsqd {
  struct dlist_head list;
  uint16_t type;
  uint16_t cls;
  uint8_t * name;
};
struct dnsmsg {
  uint16_t tid;
  bool qr;
  struct dnsqd ql;
};

static int dns_parse_packet(const uint8_t * packet, struct dnsmsg * m);
static void dns_msg_free_ql(struct dnsqd * ql);

int dns_parse(const uint8_t * packet, struct question * q)
{
  struct dnsmsg m;
  dlist_init_head(&m.ql.list);
  if(dns_parse_packet(packet, &m) != 0) {
    return -1;
  }

  q->tid = m.tid;
  q->query = m.qr;
  if(!m.qr) {
    return 0;
  }

  struct dnsqd * first = dlist_entry(m.ql.list.next, struct dnsqd, list);
  if(dlist_empty(&m.ql.list)) {
    return -1;
  }
  q->type = first->type;
  memset(q->name, 0, 512);
  snprintf(q->name, 512, "%s", first->name);

  dns_msg_free_ql(&m.ql);
  return 0;
}

static void dns_msg_free_ql(struct dnsqd * ql)
{
  struct dnsqd * p, * n;
  dlist_for_each_entry_safe(p, n, &ql->list, list) {
    free(p->name);
    dlist_del(&p->list);
    free(p); 
  }
  return;
}

static int dns_parse_message(uint8_t * msg, uint16_t size, struct dnsmsg * m);
// use the name "packet" in convention, actually it is ether frame
static int dns_parse_packet(const uint8_t * packet, struct dnsmsg * m)
{
  struct ethhdr * eth = (struct ethhdr *)packet;
  if(ntohs(eth->h_proto) != ETH_P_IP) // 802.1q or qinq not considered
    return -1;

  struct iphdr * ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
  if(ip->protocol != IPPROTO_UDP)
    return -1;

  struct udphdr * udp = (struct udphdr *)((uint8_t *)ip + ip->ihl*4);
  if(ntohs(udp->dest) != 53 && ntohs(udp->source) != 53)
    return -1;

  uint8_t * data = ((uint8_t *)udp + sizeof(struct udphdr));
  uint16_t size = ntohs(udp->len) - sizeof(struct udphdr); 
  return dns_parse_message(data, size, m);
}

static uint16_t dns_parse_qd(uint8_t * qd, uint16_t qsize, uint16_t qdcount, struct dnsqd * ql);
static int dns_parse_message(uint8_t * msg, uint16_t size, struct dnsmsg * m)
{
  struct dnshdr * dns = (struct dnshdr*)msg;
  // discard non-standard query, truncated message 
  if(dns->opcode != 0 || dns->tc != 0) {
    return -1;
  }

  m->tid = ntohs(dns->id);
  m->qr = (dns->qr == 0);

  // for response msg, only transaction ID is needed
  if(!m->qr) {
    return 0;
  }

  uint8_t * qd = (uint8_t*)dns + sizeof(struct dnshdr);
  uint16_t qsize = size - sizeof(struct dnshdr);
  uint16_t qdcount = ntohs(dns->qdcount);
  if(dns_parse_qd(qd, qsize, qdcount, &m->ql) == qdcount) {
    return 0;
  }

  dns_msg_free_ql(&m->ql);
  return -1;
}

/* layout example of 2 questions 
04 64 6f 63 73 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01
    d  o  c  s    g   o  o  g  l  e     c  o  m    [ A ] [IN ]
01 64 00 00 01 00 01
   d     [ A ] [IN ]
*/
static uint16_t dns_parse_qd(uint8_t * qd, uint16_t qsize, uint16_t qdcount, struct dnsqd * ql)
{
  uint8_t buffer[512] = {0}; // max 512 refer to rfc1035 2.3.4
  uint16_t type, cls;

  uint16_t cnt = 0;
  for(; cnt < qdcount; cnt++) {
    uint8_t i = 0, j = 0; // i index on qd, j index on buffer
    for(; i < qsize; ) {
      uint8_t lsize = qd[i]; //lsize: label size
      if(lsize > 63) //compressed message described in rfc1035 4.1.4
        return cnt; //discard it, to keep things simple
      i++;
      if(lsize == 0)
        break; // end of labels 
      memcpy(buffer+j, qd+i, lsize);
      j += lsize;
      buffer[j++] = '.';
      i += lsize;
    }
    uint8_t * name = (uint8_t*)malloc(j);
    memcpy(name, buffer, j);
    name[--j] = 0;

    struct dnsqd * q = (struct dnsqd*)malloc(sizeof(struct dnsqd));
    q->type = ntohs(*(uint16_t*)(qd+i));
    q->cls = ntohs(*(uint16_t*)(qd+i+2));
    q->name = name;

    dlist_add_tail(&q->list, &ql->list);
  }
  return cnt;
}

