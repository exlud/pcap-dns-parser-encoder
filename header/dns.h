#ifndef PROTOCOL_DNS_H
#define PROTOCOL_DNS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct question {
  uint16_t tid;
  bool query; //true for query, false for response
  uint16_t type;
#define DNS_TYPE_A (1)
#define DNS_TYPE_AAAA (28)
#define DNS_TYPE_MX (15)
  char name[512];
};

// stupid simple API for most cases
// output
//   the first question in a standard query using internet class in the first message of a packet
//   which is the normal case
// return
//   negative means error
// note
//   the 'type' and 'name' members are not filled when it's a response
int dns_parse(const uint8_t * packet, struct question * q);

#ifdef __cplusplus
}
#endif

#endif
