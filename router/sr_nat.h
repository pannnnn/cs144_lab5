
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "sr_router.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  CLOSE_WAIT
} tcp_connection_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  /*tcp_connection_state tcp_state;*/ 
  /*uint32_t ip_dst;
  uint16_t dst_port;
  time_t last_updated;
  sr_ip_hdr_t* syn_received;
  */

  struct sr_nat_connection *next;
};

struct sr_nat_syn {
  uint32_t ip_dst;
  uint16_t dst_port;
  time_t last_updated; /*received time*/
  uint8_t* syn_received;
  unsigned int len;
  struct sr_nat_syn *next;

};


struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
  /* int unsolicited; */
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  struct sr_instance *sr;
  int icmp_query;
  int tcp_established_idle;
  int tcp_transitory_idle;
  uint16_t identifier_or_port;
  struct sr_nat_syn *syn;
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

void nat_mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping *entry);
/*
void sr_nat_insert_connection(struct sr_nat_mapping *mapping,

struct sr_nat_connection *sr_nat_lookup_connection(struct sr_nat_mapping *mapping,
  uint32_t ip_dst, uint16_t dst_port);

struct sr_nat_mapping *sr_nat_internal_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

struct sr_nat_mapping *sr_nat_external_mapping(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type);*/

#endif
