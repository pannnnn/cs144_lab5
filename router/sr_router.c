/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  if (len < sizeof(sr_ethernet_hdr_t))
    return;
  uint16_t type = ethertype(packet);
  /* check if it is a ip packet */
  if (type == ethertype_ip) {
    if (sr->nat) {
      nat_handle_ip(sr, packet, len, interface);
    } else {
      sr_handle_ip(sr, packet, len, interface);
    }

  /* check if it is a arp packet */
  } else if (type == ethertype_arp) {
    /* check if it is a valid arp packet */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
      return;

    sr_arp_hdr_t* arp_packet = (sr_arp_hdr_t*) (packet +
                                                sizeof(sr_ethernet_hdr_t));


    /* receive an arp request and reply it*/
    if (ntohs(arp_packet->ar_op) == arp_op_request) {
      if (arp_packet->ar_tip == sr_get_interface(sr, interface)->ip)
        arp_reply(sr, arp_packet, interface);
    /* receive an arp reply and forward package*/
    } else if (ntohs(arp_packet->ar_op) == arp_op_reply) {
      if (arp_packet->ar_tip == sr_get_interface(sr, interface)->ip) {
        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache),
                                                  arp_packet->ar_sha,
                                                  arp_packet->ar_sip);
        /* take out and deal all the requests associated with that ARP reply */
        if (req) {
          struct sr_packet* req_packet = req->packets;
          while (req_packet) {

            sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)
                                              req_packet->buf;
            memcpy(ethernet_hdr->ether_dhost, arp_packet->ar_sha, 6);
            memcpy(ethernet_hdr->ether_shost, arp_packet->ar_tha, 6);
            sr_send_packet(sr, req_packet->buf, req_packet->len,
                           req_packet->iface);
            req_packet = req_packet->next;
          }
          sr_arpreq_destroy(&(sr->cache), req);
        }
      }
    }
  }
}/* end sr_ForwardPacket */


/*
  Handle a ip packet accordingly based on thier properties in the header
*/
void sr_handle_ip(struct sr_instance* sr,
                  uint8_t* packet,
                  unsigned int len,
                  char* interface)
{
  sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*)
                           (packet + sizeof(sr_ethernet_hdr_t));

  /* check if it's in one of the sr's interfaces */
  if (valid_ip_packet(ip_packet, len - sizeof(sr_ethernet_hdr_t))) {
    struct sr_if* iface = in_if_list(sr, (uint32_t) ip_packet->ip_dst);
    if(iface){

      /* it contains icmp protocal */
      if(ip_packet->ip_p == ip_protocol_icmp) {
          sr_icmp_hdr_t* received_packet = (sr_icmp_hdr_t*)
                                           (packet +
                                            sizeof(sr_ethernet_hdr_t) +
                                            ip_packet->ip_hl * 4);
          int received_sum  = received_packet->icmp_sum;
          received_packet->icmp_sum = 0;
          int icmp_cksum = cksum(received_packet,
                                 len - sizeof(sr_ethernet_hdr_t) +
                                  ip_packet->ip_hl * 4);
          /* To see if a packet is still valid by looking at the checksum */
          if (icmp_cksum != received_sum) {
            /*return;*/
          }
          uint8_t *echo_reply = malloc(len);
          sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (echo_reply +
                                                sizeof(sr_ethernet_hdr_t));
          memcpy(ip_hdr, ip_packet, len - sizeof(sr_ethernet_hdr_t));
          /* Set general icmp header properties */
          sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)
                                    (echo_reply +
                                     sizeof(sr_ethernet_hdr_t) +
                                     ip_hdr->ip_hl * 4);
          icmp_hdr->icmp_type = 0;
          icmp_hdr->icmp_code = 0;
          int icmp_len = len - sizeof(sr_ethernet_hdr_t) -
                               ip_packet->ip_hl * 4;
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);
          /* Set general ip header properties */
          ip_hdr->ip_ttl = 100;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_src = ip_packet->ip_dst;
          ip_hdr->ip_dst = ip_packet->ip_src;
          ip_hdr->ip_sum = cksum(ip_hdr, ip_packet->ip_hl*4);
          struct sr_rt* next_hop = get_next_hop(sr, ip_hdr->ip_dst);
          struct sr_if* src_host = sr_get_interface(sr, next_hop->interface);
          sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) echo_reply;
          memcpy(ethernet_hdr->ether_shost, src_host->addr, 6);

          ethernet_hdr->ether_type = htons(ethertype_ip);
          struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache),
                                                         ip_hdr->ip_dst);
          /*
            Check if we find a matching(ip->mac) in cache, utilize the
            matching to find destination mac for a specific ip and
            send out the packet accordingly
          */
          if (entry) {
            memcpy(ethernet_hdr->ether_dhost, entry->mac, 6);
            sr_send_packet(sr, echo_reply, len, next_hop->interface);
            free(entry);
          } else {;
            /*
              If a entry can not be found, simply add a new request to the
              arp cache queue trying to get a new entry every second
            */
            sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, echo_reply,
                                 len, next_hop->interface);
          }
          return;
      } else {
        /* it contains protocals other than icmp and has type3 or type11 */
        struct sr_rt* next_hop = get_next_hop(sr, ip_packet->ip_src);
        icmp_type3_type11(sr, ip_packet, 3, 3, next_hop->interface);
      }
    } else {
      /* Try to find the outgoing interface at the router for that specific
      ip packet */
      struct sr_rt* next_hop = get_next_hop(sr, ip_packet->ip_dst);
      if (next_hop) {
        /*
          Send back a type 11 icmp packet through found interface if ttl
          becomes 0 when a packet arrive in the router
          */
        if (ip_packet->ip_ttl == 1) {
          struct sr_rt* return_route = get_next_hop(sr, ip_packet->ip_src);
          icmp_type3_type11(sr, ip_packet, 11, 0, return_route->interface);
          return;
        }
        /* Set up ethernet header and ip header accordingly */
        struct sr_if* new_iface = sr_get_interface(sr, next_hop->interface);
        ip_packet->ip_ttl--;
        ip_packet->ip_sum = 0;

        uint8_t* new_ether = malloc(len);
        sr_ethernet_hdr_t* new_ether_hdr = (sr_ethernet_hdr_t*) new_ether;
        sr_ip_hdr_t* new_ip = (sr_ip_hdr_t*) (new_ether +
                                              sizeof(sr_ethernet_hdr_t));

        memcpy(new_ip, ip_packet, len - sizeof(sr_ethernet_hdr_t));
        new_ip->ip_sum = cksum(new_ip, new_ip->ip_hl*4);
        memcpy(new_ether_hdr->ether_shost, new_iface->addr, 6);

        new_ether_hdr->ether_type = htons(ethertype_ip);

        /*
          Check if a entry for exsits for a specific ip address, if it is,
          send the packet directly, else queue the packet and a
          associated request waited to be sent every second.
        */
        struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache),
                                                       new_ip->ip_dst);
        if (entry) {
          memcpy(new_ether_hdr->ether_dhost, entry->mac, 6);
          sr_send_packet(sr, new_ether, len, next_hop->interface);
          free(entry);
        } else {
          sr_arpcache_queuereq(&(sr->cache), ip_packet->ip_dst, new_ether,
                               len, next_hop->interface);
        }
        return;
      /*ived_packet,
                                 len - sizeof(sr_ethernet_hdr_t) +
                                  ip_packet->ip_hl * 4);
          /* To see if a packet is still valid by looking at
        Sent if there is a non-existent route to the destination IP
      */
      } else {
        struct sr_rt* return_route = get_next_hop(sr, ip_packet->ip_src);
        icmp_type3_type11(sr, ip_packet, 3, 0, return_route->interface);
      }
    }
  }
  return;
}

/*
Function to send and excute type type and code code related message out to
corresponding interface.
*/
void icmp_type3_type11(struct sr_instance* sr, sr_ip_hdr_t* ip_packet,
                      int type, int code, char* interface) {
  int malloc_len = sizeof(sr_ethernet_hdr_t) +
                   sizeof(sr_ip_hdr_t) +
                   sizeof(sr_icmp_t3_hdr_t);
  uint8_t* icmp_type3 = malloc(malloc_len);
  struct sr_icmp_t3_hdr* icmp_hdr = (struct sr_icmp_t3_hdr*)
                             (icmp_type3 + sizeof(sr_ethernet_hdr_t) +
                              sizeof(sr_ip_hdr_t));

  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;

  memcpy(icmp_hdr->data, ip_packet, ICMP_DATA_SIZE);
  /* Calculate icmp header's checksum before ip header's checksum */
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));


  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (icmp_type3 +
                                        sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_v = 4;
  ip_hdr->ip_tos = ip_packet->ip_tos;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_len = htons(malloc_len - sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_ttl = 100;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_id = ip_packet->ip_id;

  struct sr_if* iface = sr_get_interface(sr, interface);
  if (type == 3 && code == 3) {
    ip_hdr->ip_src = ip_packet->ip_dst;
  } else {
    ip_hdr->ip_src = iface->ip;
  }
  ip_hdr->ip_dst = ip_packet->ip_src;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);


  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) icmp_type3;


  memcpy(ethernet_hdr->ether_shost, iface->addr, 6);
  ethernet_hdr->ether_type = htons(ethertype_ip);
  /*
    Look up in the cache to see if we can find a matched mac address to a
    specific ip address without sending an arp request again.
  */
  struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache),
                                                 ip_hdr->ip_dst);
  if (entry) {
    memcpy(ethernet_hdr->ether_dhost, entry->mac, 6);
    sr_send_packet(sr, icmp_type3, malloc_len, iface->name);
    free(entry);
  } else {
    sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, icmp_type3,
                         malloc_len, iface->name);
    free(icmp_type3);
  }
}

int valid_ip_packet(sr_ip_hdr_t* packet, unsigned int len) {
  /* Check for minimum packet length */

  /* Check for minimum header length*/
  if (packet->ip_hl < 5)
      return 0;

  /*Compute checksum*/
  uint16_t packet_ip_sum = packet->ip_sum;
  packet->ip_sum = 0;
  uint16_t checksum = cksum(packet, packet->ip_hl*4);

  /* Invalid checksum */
  if (checksum != packet_ip_sum)
      return 0;

  packet->ip_sum = packet_ip_sum;
  return 1;

}

/* reply apr request with an icmp message */
void arp_reply(struct sr_instance* sr, sr_arp_hdr_t* packet, char* interface) {
  struct sr_if* iface = sr_get_interface(sr, interface);
  if (packet->ar_tip == iface->ip) {
    int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* reply = malloc(reply_len);
    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) reply;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (reply +
                                             sizeof(sr_ethernet_hdr_t));

    /* Set up arp header. */
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_reply);

    /* Do the memory copying*/
    memcpy(arp_hdr->ar_sha, iface->addr, 6);
    arp_hdr->ar_sip = iface->ip;
    memcpy(arp_hdr->ar_tha, packet->ar_sha, 6);
    arp_hdr->ar_tip = packet->ar_sip;

    memcpy(ethernet_hdr->ether_dhost, packet->ar_sha, 6);
    memcpy(ethernet_hdr->ether_shost, iface->addr, 6);
    ethernet_hdr->ether_type = htons(ethertype_arp);
    sr_send_packet(sr, reply, reply_len, iface->name);
    /* Free the memory we allocated*/
    free(reply);
  }
  return;
}

/* check if a specific ip matches any of the interface in the router */
struct sr_if* in_if_list(struct sr_instance* sr, uint32_t ip) {
  struct sr_if* if_walker = sr->if_list;
  /* Loop through all interfaces.*/
  while(if_walker) {
    if (if_walker->ip == ip) {
      return if_walker;
    }
    if_walker = if_walker->next;
  }
  return NULL;
}

void nat_handle_ip(struct sr_instance* sr,
                   uint8_t* packet,
                   unsigned int len,
                   char* interface)
{
  sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*)
                           (packet + sizeof(sr_ethernet_hdr_t));
  if (valid_ip_packet(ip_packet, len - sizeof(sr_ethernet_hdr_t))) {
    struct sr_if* iface = in_if_list(sr, (uint32_t) ip_packet->ip_dst);
    /*Inbound to Inbound*/
    if (sr_get_interface(sr, ETH1)->ip == sr_get_interface(sr, interface)->ip && iface) {
      if (ip_packet->ip_p == ip_protocol_icmp) {
        /* Since it is internal to internal, handle it the way we used to. */
        sr_handle_ip(sr, packet, len, ETH1);
      } else if (ip_packet->ip_p == ip_protocol_tcp) {
        /* Validdate the tcp packet with pseudo header*/
        if (valid_tcp_packet(ip_packet, len)) {
          sr_handle_ip(sr, packet, len, ETH1);
        }
      }
    } else if (sr_get_interface(sr, ETH1)->ip == sr_get_interface(sr, interface)->ip) {
      /* The packet is going out */
     
      if (ip_packet->ip_p == ip_protocol_icmp) {
        /* if not matching is found for the destination then drop the packet and send back dest unreachable */
        if (get_next_hop(sr,ip_packet->ip_dst) == NULL){
          icmp_type3_type11(sr, ip_packet, 3, 0, ETH1);
        }else{
          sr_icmp_t0_hdr_t* icmp_packet = (sr_icmp_t0_hdr_t*) (ip_packet + ip_packet->ip_hl*4);
          icmp_packet->icmp_sum = 0;
          struct sr_nat_mapping* lookup_int = sr_nat_lookup_internal(sr->nat, 
                                                                ip_packet->ip_src, 
                                                                icmp_packet->icmp_id, 
                                                                nat_mapping_icmp);
          if (!lookup_int) {
            lookup_int = sr_nat_insert_mapping(sr->nat, ip_packet->ip_src,
                                              icmp_packet->icmp_id,
                                              nat_mapping_icmp);
          }
          icmp_packet->icmp_id = lookup_int->aux_ext;
          icmp_packet->icmp_sum = cksum(icmp_packet, len-ip_packet->ip_hl*4);
          ip_packet->ip_src = lookup_int->ip_ext;
          lookup_int->last_updated = time(NULL);
          ip_packet->ip_sum = 0;
          ip_packet->ip_sum = cksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
          sr_handle_ip(sr, packet, len, ETH1);
        }
      } else if (ip_packet->ip_p == ip_protocol_tcp) {
          printf("Handling internal to external TCP\n");
          fflush(stdout);
          sr_tcp_hdr_t* tcp_packet = (sr_tcp_hdr_t*) (ip_packet + ip_packet->ip_hl*4);
          struct sr_nat_mapping* lookup_int = sr_nat_lookup_internal(sr->nat,
                                                                ip_packet->ip_src,
                                                                tcp_packet->src_port,
                                                                nat_mapping_tcp);
          if (!lookup_int && !((ntohs(tcp_packet->flags) & 0x2) >> 1)) {
          /**No mapping and wants to sent a tcp packet out*/
            return;
          } else if ((ntohs(tcp_packet->flags) & 0x2) >> 1) {
              if (lookup_int) {
                pthread_mutex_lock(&((sr->nat)->lock));
                struct sr_nat_mapping *int_mapping = sr_nat_internal_mapping(sr->nat,
                                                                      ip_packet->ip_src,
                                                                      tcp_packet->src_port,
                                                                      nat_mapping_tcp);
                struct sr_nat_connection *lookup_conns = sr_nat_lookup_connection(int_mapping,
                                                                      ip_packet->ip_dst,
                                                                      tcp_packet->dst_port);
                if (!lookup_conns) {
                  sr_nat_insert_connection(int_mapping, ip_packet->ip_dst, tcp_packet->dst_port);
                } else if (lookup_conns->tcp_state == SYN_RECEIVED) {
                  lookup_conns->tcp_state = ESTABLISHED;
                  if (lookup_conns->syn_received) free(lookup_conns->syn_received);
                } else if (lookup_conns->tcp_state == CLOSE_WAIT) {
                  lookup_conns->tcp_state = SYN_SENT;
                }
                pthread_mutex_lock(&((sr->nat)->lock));
                tcp_packet->src_port = lookup_int->aux_ext;
                ip_packet->ip_src = lookup_int->ip_ext;
                print_addr_ip_int(lookup_int->ip_ext);
                tcp_checksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
                ip_packet->ip_sum = 0;
                ip_packet->ip_sum = cksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
                iface = sr_get_interface(sr, ETH2);
                sr_handle_ip(sr, packet, len, iface->name);
                free(lookup_int);
              } else {
                printf("SYN FLAG SENT OUT\n");
                fflush(stdout);
                pthread_mutex_lock(&((sr->nat)->lock));
                struct sr_nat_mapping *int_mapping = sr_nat_insert_mapping(sr->nat,
                                                                 ip_packet->ip_src,
                                                                 tcp_packet->src_port,
                                                                 nat_mapping_tcp);

                sr_nat_insert_connection(int_mapping, ip_packet->ip_dst,
                                         tcp_packet->dst_port);
                pthread_mutex_unlock(&((sr->nat)->lock));
                lookup_int = sr_nat_lookup_internal(sr->nat,
                                                    ip_packet->ip_src,
                                                    tcp_packet->src_port,
                                                    nat_mapping_tcp);
                tcp_packet->src_port = lookup_int->aux_ext;
                ip_packet->ip_src = lookup_int->ip_ext;
                print_addr_ip_int(lookup_int->ip_ext);
                tcp_checksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
                ip_packet->ip_sum = 0;
                ip_packet->ip_sum = cksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
                print_hdr_ip(ip_packet);
                iface = sr_get_interface(sr, ETH2);
                /*SHOULD WE UPDATE THE ETHERNET PACKET HERE?*/
                sr_handle_ip(sr, packet, len, iface->name);
              }
          } else if ((ntohs(tcp_packet->flags) & 0x1)) {
            pthread_mutex_lock(&((sr->nat)->lock));
            struct sr_nat_mapping *int_mapping = sr_nat_internal_mapping(sr->nat,
                                                                  ip_packet->ip_src,
                                                                  tcp_packet->src_port,
                                                                  nat_mapping_tcp);
            struct sr_nat_connection *lookup_conns = sr_nat_lookup_connection(int_mapping,
                                                                  ip_packet->ip_dst,
                                                                  tcp_packet->dst_port);
            if (lookup_conns) lookup_conns->tcp_state = CLOSE_WAIT;

            pthread_mutex_unlock(&((sr->nat)->lock));
            tcp_packet->src_port = lookup_int->aux_ext;
            ip_packet->ip_src = lookup_int->ip_ext;
            tcp_checksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
            ip_packet->ip_sum = 0;
            ip_packet->ip_sum = cksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
            iface = sr_get_interface(sr, ETH2);
            /*SHOULD WE UPDATE THE ETHERNET PACKET HERE?*/
            sr_handle_ip(sr, packet, len, iface->name);
          }
      }
    } else {
      if (sr_get_interface(sr, ETH2)->ip == sr_get_interface(sr, interface)->ip) {
        if (ip_packet->ip_p == ip_protocol_icmp) {
            sr_icmp_t0_hdr_t* icmp_packet = (sr_icmp_t0_hdr_t*) (ip_packet + ip_packet->ip_hl*4);
            icmp_packet->icmp_sum = 0;
            struct sr_nat_mapping* lookup_ext = sr_nat_lookup_external(sr->nat, 
                                                                icmp_packet->icmp_id, 
                                                                nat_mapping_icmp);
            if(iface){
              if (!lookup_ext) {
                /* handle imcp or tcp targeted to one of the interfaces from server1 or server2*/
                sr_handle_ip(sr, packet, len, ETH2);
              }else{
                /* handle icmp reply from server*/
                icmp_packet->icmp_id = lookup_ext->aux_int;
                icmp_packet->icmp_sum = cksum(icmp_packet, len-ip_packet->ip_hl*4);
                ip_packet->ip_src = sr_get_interface(sr, ETH1)->ip;
                ip_packet->ip_dst = lookup_ext->ip_int;
                lookup_ext->last_updated = time(NULL);
                ip_packet->ip_sum = 0;
                ip_packet->ip_sum = cksum(ip_packet, len-sizeof(sr_ethernet_hdr_t));
                sr_handle_ip(sr, packet, len, ETH2);
              }
            }else{
              /* imcp, tcp, or other packets sent to somewhere else*/
              sr_handle_ip(sr, packet, len, ETH2);
            }
        }
      }
    }
  }
}

int valid_tcp_packet(sr_ip_hdr_t *packet, unsigned int len) {
  int length = len - packet->ip_hl*4;
  sr_tcp_hdr_t* tcp_hdr  = (sr_tcp_hdr_t*) (packet + 
                                           sizeof(sr_ethernet_hdr_t) + 
                                           packet->ip_hl*4);
  sr_tcp_pseudo_hdr_t* tcp_pseudo_hdr = malloc(sizeof(sr_tcp_pseudo_hdr_t) + 
                                               length);
  uint16_t tcp_checksum = 0;
  uint16_t packet_tcp_checksum = tcp_hdr->checksum;
  tcp_hdr->checksum = 0;
  memcpy(tcp_pseudo_hdr + sizeof(sr_tcp_pseudo_hdr_t), tcp_hdr, length);
  tcp_pseudo_hdr->src_ip = packet->ip_src;
  tcp_pseudo_hdr->dst_ip = packet->ip_dst;
  tcp_pseudo_hdr->reserved = 0;
  tcp_pseudo_hdr->protocol = ip_protocol_tcp;
  tcp_pseudo_hdr->length = htons(length);

  tcp_checksum = cksum(tcp_pseudo_hdr, sizeof(sr_tcp_pseudo_hdr_t) + length);
  if (tcp_checksum == packet_tcp_checksum) {
    free(tcp_pseudo_hdr);
    return 1;
  } else {
    free(tcp_pseudo_hdr);
    return 0;
  }
}

void tcp_checksum(sr_ip_hdr_t *packet, unsigned int len){
  int length = len - packet->ip_hl*4;
  sr_tcp_hdr_t* tcp_hdr  = (sr_tcp_hdr_t*) (packet +
                                            packet->ip_hl*4);
  sr_tcp_pseudo_hdr_t* tcp_pseudo_hdr = malloc(sizeof(sr_tcp_pseudo_hdr_t) +
                                               length);
  memcpy(tcp_pseudo_hdr + sizeof(sr_tcp_pseudo_hdr_t), tcp_hdr, length);
  tcp_pseudo_hdr->src_ip = packet->ip_src;
  tcp_pseudo_hdr->dst_ip = packet->ip_dst;
  tcp_pseudo_hdr->reserved = 0;
  tcp_pseudo_hdr->protocol = ip_protocol_tcp;
  tcp_pseudo_hdr->length = htons(length);
  tcp_hdr->checksum = 0;
  tcp_hdr->checksum  = cksum(tcp_pseudo_hdr, sizeof(sr_tcp_pseudo_hdr_t) + length);
  free(tcp_pseudo_hdr);
}

