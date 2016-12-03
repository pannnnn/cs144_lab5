
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_if.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));
    Debug("[TIMEOUT]\n");
    time_t curtime = time(NULL);
    struct sr_nat_syn *curr_syn = nat->syn;
    struct sr_nat_syn *next_syn = NULL;
    while(curr_syn){
      if (difftime(curr_syn->last_updated, curtime) >= 6){
        next_syn = curr_syn->next;
        sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*) (curr_syn->syn_received + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if(sr_nat_lookup_external(nat, tcp_hdr->dst_port, nat_mapping_tcp)){
          nat_handle_ip(nat->sr, curr_syn->syn_received , curr_syn->len, ETH2);
        }else{
          sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (curr_syn->syn_received + sizeof(sr_ethernet_hdr_t));
          icmp_type3_type11(nat->sr, ip_hdr, 3, 3, ETH2);
        }
        Debug("[TIMEOUT] %lf", difftime(curr_syn->last_updated, curtime));
        curr_syn = next_syn;

      }else{
        
        curr_syn = curr_syn->next;
      }
    }
    /* handle periodic tasks here */
    struct sr_nat_mapping* curr = nat->mappings;
    struct sr_nat_mapping* next = NULL;
    while (curr){
        if (curr->type == nat_mapping_icmp){
          if (difftime(curtime,curr->last_updated) > nat->icmp_query){
            next = curr->next;
            nat_mapping_destroy(nat, curr);
            curr = next;
          }else{
            curr = curr->next;
          }
        }else if (curr->type == nat_mapping_tcp){
          if (difftime(curtime,curr->last_updated) > nat->tcp_established_idle){
            next = curr->next;
            nat_mapping_destroy(nat, curr);
            curr = next;
          }else{
            curr = curr->next;
          }
        }
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *curr = nat->mappings;

  while (curr) {
    if (curr->type == type && curr->aux_ext == aux_ext) {
      curr->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, curr, sizeof(struct sr_nat_mapping));
      pthread_mutex_unlock(&(nat->lock));
    }
    curr = curr->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *curr = nat->mappings;

  while (curr) {
    if (curr->type == type && curr->ip_int == ip_int &&
        curr->aux_int == aux_int) {
      curr->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, curr, sizeof(struct sr_nat_mapping));
      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }
    printf("COPY:::%d\n", copy);
    curr = curr->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = sr_get_interface(nat->sr, ETH2)->ip;
  mapping->aux_int = aux_int;
  if (nat->identifier_or_port > 35876) {
    nat->identifier_or_port = 1389;
  }
  mapping->aux_ext = nat->identifier_or_port;
  nat->identifier_or_port++;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->next = nat->mappings;
  nat->mappings = mapping;
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
/*
void sr_nat_insert_connection(struct sr_nat_mapping *mapping,
  uint32_t ip_dst, uint16_t dst_port) {
    struct sr_nat_connection *conn = malloc(sizeof(struct sr_nat_connection));
    conn->tcp_state = SYN_SENT;
    conn->ip_dst = ip_dst;
    conn->dst_port = dst_port;
    conn->last_updated = time(NULL);
    conn->syn_received = NULL;
    conn->next = mapping->conns;
    mapping->conns = conn;
    return;
}

struct sr_nat_connection *sr_nat_lookup_connection(struct sr_nat_mapping *mapping,
  uint32_t ip_dst, uint16_t dst_port) {
      struct sr_nat_connection *curr = mapping->conns;
      while (curr) {
        if (curr->ip_dst == ip_dst && curr->dst_port == dst_port) {
          curr->last_updated = time(NULL);
          return curr;
        }
      }
      return NULL;
  }

struct sr_nat_mapping *sr_nat_internal_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

  struct sr_nat_mapping *curr = nat->mappings;

  while (curr) {
    if (curr->type == type && curr->ip_int == ip_int &&
        curr->aux_int == aux_int) {
      curr->last_updated = time(NULL);
      return curr;
    }
    curr = curr->next;
  }
  return NULL;
}

struct sr_nat_mapping *sr_nat_external_mapping(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type) {

  struct sr_nat_mapping *curr = nat->mappings;

  while (curr) {
    if (curr->type == type && curr->aux_ext == aux_ext) {
      curr->last_updated = time(NULL);
      return curr;
    }
    curr = curr->next;
  }

  return NULL;
}
*/
/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void nat_mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping *entry) {
    pthread_mutex_lock(&(nat->lock));
    
    if (entry) {
        struct sr_nat_mapping *mapping, *prev = NULL, *next = NULL; 
        for (mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
            if (mapping == entry) {                
                if (prev) {
                    next = mapping->next;
                    prev->next = next;
                } 
                else {
                    next = mapping->next;
                    nat->mappings = next;
                }
                
                break;
            }
            prev = mapping;
        }
        
/*        struct sr_nat_connection *conn, *nxt;
        
        for (conn = entry->conns; conn; conn = nxt) {
            nxt = conn->next;
            if (conn->syn_received)
                free(conn->syn_received);
            free(conn);
        }
*/        
        free(entry);
    }
    
    pthread_mutex_unlock(&(nat->lock));
}