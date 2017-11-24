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
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
    if (sr->nat_active) {
      sr_nat_init(sr->nat);
    }
} /* -- sr_init -- */

struct sr_if* sr_get_interface_by_ip(struct sr_instance* sr, uint32_t ip) {
  struct sr_if* iterator = 0;
  iterator = sr->if_list;
  sr_print_if_list(sr);
  while (iterator) {
    if (ntohl(iterator->ip) == ntohl(ip)) {
      return iterator;
    }
    iterator = iterator->next;
  }

  return NULL;
}

void send_icmp_echo_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  uint8_t* data = (uint8_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  uint8_t* new_packet = (uint8_t*) malloc(len);

  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) new_packet;
  struct sr_if* iface = sr_get_interface(sr, interface);
  ethernet_header->ether_type = htons(ethertype_ip);
  memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
  sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t));
  new_ip_header->ip_hl = ip_header->ip_hl;
  new_ip_header->ip_v = ip_header->ip_v;
  new_ip_header->ip_tos = ip_header->ip_tos;
  new_ip_header->ip_len = ip_header->ip_len;
  new_ip_header->ip_id = ip_header->ip_id;
  new_ip_header->ip_off = ip_header->ip_off;
  new_ip_header->ip_ttl = IP_TTL;
  new_ip_header->ip_p = ip_protocol_icmp;
  new_ip_header->ip_sum = 0;     
  new_ip_header->ip_src = ip_header->ip_dst;
  new_ip_header->ip_dst = ip_header->ip_src;
  new_ip_header->ip_sum = cksum((void *)new_ip_header, sizeof(sr_ip_hdr_t));
  sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_header->icmp_type = 0;
  icmp_header->icmp_code = 0; 
  icmp_header->icmp_sum = 0;
  memcpy((void*)(new_packet + sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)), data, ntohs(new_ip_header->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
  icmp_header->icmp_sum = cksum((void *)icmp_header, ntohs(new_ip_header->ip_len) - sizeof(sr_ip_hdr_t));

  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, new_ip_header->ip_dst);
  if (entry) {
    memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
    int error = sr_send_packet(sr, new_packet, len, iface->name);
    if (!error) {
      printf("Sent ICMP reply echo successfully\n");
    } else {
      printf("ICMP echo reply failed\n");
    }
    free(entry);
  } else {
    memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
    sr_arpcache_queuereq(&sr->cache, new_ip_header->ip_dst , new_packet , len, iface->name);
  }
  free(new_packet);
}

void received_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
  if (len - sizeof(sr_ethernet_hdr_t) < sizeof(sr_ip_hdr_t)) {
    /* Invalid IP header */
    printf("Invalid IP Header\n");
    return;
  }

  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  if (ip_header->ip_v != 4) {
    printf("Not IPV4\n");
    return;
  }

  if (sr->nat_active) {
    if (ip_header->ip_p == 6)
    {
      int success = nat_received_tcp(sr, packet, interface, len);
      if (success == -1)
      {
        printf("NAT handling TCP failed\n");
        return;
      }
    }
    else if (ip_header->ip_p == ip_protocol_icmp)
    {
      int success = nat_received_icmp(sr, packet, interface, len);
      if (success == -1)
      {
        printf("NAT handling ICMP failed\n");
        return;
      }
    }
  }

  /* Checksum validation */
  uint16_t sent_sum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t received_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  if (sent_sum != received_sum) {
    printf("Invalid IP Checksum\n");
    return;
  }
  ip_header->ip_sum = received_sum;
  
  struct sr_if* matched_if = sr_get_interface_by_ip(sr, ip_header->ip_dst);

  if (matched_if != NULL) {
    if (ip_header->ip_p != ip_protocol_icmp) {
      printf("Sending ICMP Port Unreachable\n");
      send_icmp_t3(sr, packet, 3, 3 , len, interface);
      return;
    }

    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    uint16_t sent_sum = icmp_header->icmp_sum;
    icmp_header->icmp_sum = 0;
    uint16_t received_sum = cksum((void *) icmp_header, ntohs(ip_header->ip_len) - sizeof(sr_ip_hdr_t)); 
    if (sent_sum != received_sum) {
      printf("Invalid ICMP checksum\n");
      return;
    }
    printf("Sending ICMP Echo\n");
    send_icmp_echo_reply(sr, packet, len, interface);
  } else {
    char* next_hop = sr_lpm(sr, ip_header->ip_dst);
    if (next_hop == NULL) {
      printf("Can't find next hop\n");
      send_icmp_t3(sr, packet, 3, 0, len, interface);
      return;
    }

    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) packet;
    struct sr_if* iface = sr_get_interface(sr, next_hop);
    uint8_t temp = ip_header->ip_ttl;
    temp--;
    if (temp <= 0) {
      send_icmp_t3(sr, packet, 11, 0, len, next_hop);
      return;
    }
    ip_header->ip_ttl = temp;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
    if (entry) {
      memcpy(ether_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
      memcpy(ether_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
      int error = sr_send_packet(sr, (uint8_t*) packet, len, next_hop);
      if (!error) {
        printf("Forwarded IP sucessfully\n");
      } else {
        printf("Forward IP Failed\n");
      }
      free(entry);
    } else {
      memcpy(ether_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
      sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, next_hop);
    }
  }
}

char* sr_lpm(struct sr_instance* sr, uint32_t ip) {
  if (!sr->routing_table) {
    return NULL;
  }

  struct sr_rt* match = NULL;
  struct sr_rt* i = sr->routing_table;
  while (i) {
    uint32_t i_prefix = ntohl(i->dest.s_addr) & ntohl(i->mask.s_addr);
    uint32_t ip_prefix = ntohl(ip) & ntohl(i->mask.s_addr);
    if (i_prefix == ip_prefix && (match == NULL || ntohl(i->mask.s_addr) > ntohl(match->mask.s_addr))) {
      match = i;
    }
    i = i->next;
  }

  if (!match) {
    return NULL;
  }

  return match->interface;
}

void received_arp_req(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
  sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* iface = sr_get_interface(sr, interface);
  print_hdrs(packet, len);
  if (arp_header->ar_tip != iface->ip) {
    return;
  }

  uint8_t* arp_reply = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t* reply_eth_h = (sr_ethernet_hdr_t*) arp_reply;
  sr_arp_hdr_t* reply_arp_h = (sr_arp_hdr_t*) (arp_reply + sizeof(sr_ethernet_hdr_t));

  /* Ethernet header configuration */
  memcpy(reply_eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_eth_h->ether_shost, iface->addr, ETHER_ADDR_LEN);
  reply_eth_h->ether_type = htons(ethertype_arp);

  /* ARP header configuration */
  reply_arp_h->ar_hrd = htons(arp_hrd_ethernet);
  reply_arp_h->ar_pro = htons(0x800);
  reply_arp_h->ar_hln = ETHER_ADDR_LEN;
  reply_arp_h->ar_pln = 4;
  reply_arp_h->ar_op = htons(arp_op_reply);
  memcpy(reply_arp_h->ar_sha, iface->addr, ETHER_ADDR_LEN);
  reply_arp_h->ar_sip = iface->ip;
  memcpy(reply_arp_h->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
  reply_arp_h->ar_tip = arp_header->ar_sip;
  int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  
  int error = sr_send_packet(sr, arp_reply, packet_size, interface);

  if (!error) {
    printf("ARP reply successfully sent!\n");
    print_hdrs(arp_reply, packet_size);
  } else {
    printf("ARP reply failed\n");
  }
  free(arp_reply);
}

void received_arp_rep(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
  sr_arpcache_dump(&sr->cache);
  if (req) {
    struct sr_packet* pkt;
    for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
      sr_ethernet_hdr_t* ether = (sr_ethernet_hdr_t*) pkt->buf;
      memcpy(ether->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
      int error = sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
      if (!error) {
        printf("Processed ARP reply\n");
      } else {
        printf("ARP processing failed\n");
      }
    }
    sr_arpreq_destroy(&sr->cache, req);
  }
}

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

  if (sr->nat_active) {
    struct sr_if *external_iface = sr_get_interface(sr, "eth2");
    sr->nat->external_ip = external_iface->ip;
  }

  if (len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }

  /* fill in code here */
  uint16_t e_type = ethertype(packet);

  if (e_type == ethertype_arp) {
    printf("<<ARP>>\n");

    sr_arp_hdr_t* arp_h = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    uint16_t arp_op = ntohs(arp_h->ar_op);
    if (arp_op == arp_op_request) {
      printf("ARP request\n");
      print_hdrs(packet, len);
      received_arp_req(sr, packet, len, interface);
    } else if(arp_op == arp_op_reply) {
      printf("ARP reply\n");
      print_hdrs(packet, len);
      received_arp_rep(sr, packet, len, interface);
    }
  }

  if (e_type == ethertype_ip) {
    printf("<<IP>>\n");
    print_hdrs(packet, len);
    received_ip(sr, packet, len, interface);
  }
}/* end sr_ForwardPacket */

