#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void print_mapping(struct sr_nat_mapping* mapping);
void send_icmp_unsol(struct sr_instance *sr, uint8_t *packet, int type, int code, uint length, char *iface);
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
  nat->icmp_timeout = 60;
  nat->tcp_established_timeout = 7440;
  nat->tcp_transitory_timeout = 300;
  memcpy(nat->external_interface, "eth2", 4);
  nat->external_ip = 0;
  nat->external_port_count = 1025;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping* mapping = nat->mappings;
  while (mapping) {
    struct sr_nat_mapping* temp = mapping;
    mapping = mapping->next;
    free(temp);
  }

  waiting_unsol_t* curr = nat->waiting_unsol;
  while (curr) {
    waiting_unsol_t* temp = curr;
    curr = curr->next;
    free(temp);
  }
  free(nat);

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    /* handle periodic tasks here */
    waiting_unsol_t* curr = nat->waiting_unsol;
    while (curr) {
      curr->waited++;
      if (curr->waited == 6) {
        send_icmp_unsol(curr->sr, curr->packet, 3, 3, curr->packet_len, curr->iface);
      }
      curr = curr->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {
  printf("NAT Lookup External\n");

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping) 
  {
    if ((mapping->type == type) && (mapping->aux_ext == aux_ext)) {
      printf("Making Copy\n");
      copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      copy->type = mapping->type;
      copy->ip_int = mapping->ip_int;
      copy->ip_ext = mapping->ip_ext;
      copy->aux_int = mapping->aux_int;
      copy->aux_ext = mapping->aux_ext;
      copy->last_updated = mapping->last_updated;
      copy->conns = mapping->conns;
      copy->next = mapping->next;
      printf("Copy Made\n");
      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  printf("NAT Lookup Internal\n");
  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping)
  {
    if ((mapping->type == type) 
        && (mapping->aux_int == aux_int) 
        && (mapping->ip_int == ip_int))
    {
      copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      copy->type = mapping->type;
      copy->ip_int = mapping->ip_int;
      copy->ip_ext = mapping->ip_ext;
      copy->aux_int = mapping->aux_int;
      copy->aux_ext = mapping->aux_ext;
      copy->last_updated = mapping->last_updated;
      copy->conns = mapping->conns;
      copy->next = mapping->next;
      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  printf("NAT Insert Mapping\n");
  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->ip_ext = nat->external_ip;
  printf("External Port Count: %d\n",nat->external_port_count);
  if (nat->external_port_count == 65000) {
    mapping->aux_ext = 1025;
    nat->external_port_count = 1026;
  } else {
    mapping->aux_ext = nat->external_port_count;
    nat->external_port_count++;
  }
  mapping->next = NULL;
  mapping->conns = NULL;

  struct sr_nat_mapping* curr = nat->mappings;
  if (!curr) {
    nat->mappings = mapping;
  } else {
    printf("A\n");
    while (curr->next) {
      curr = curr->next;
    }
    curr->next = mapping;
    printf("B\n");
  }
  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

void print_binary(uint8_t control) {
  while (control) {
    if (control&1) {
      printf("1");
    } else {
      printf("0");
    }
    control = control>>1;
  }
  printf("\n");
}

int is_syn(uint8_t *packet) {
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet 
                                            + sizeof(sr_ethernet_hdr_t)
                                            + sizeof(sr_ip_hdr_t));
  uint8_t control = tcp_hdr->control;
  int fin_set = (control & 1) != 0 ? 1 : 0;
  int syn_set = (control & (1<<1)) != 0 ? 1 : 0;
  int psh_set = (control & (1<<3)) != 0 ? 1 : 0;
  int ack_set = (control & (1<<4)) != 0 ? 1 : 0;
  
  print_binary(control);
  printf("FIN:%d\nSYN:%d\nPSH:%d\nACK:%d\n",fin_set,syn_set,psh_set,ack_set);
  if (syn_set && !ack_set && !fin_set && !psh_set) {
    return 1;
  }

  return 0;
}

int nat_received_icmp(struct sr_instance* sr, uint8_t* packet, char* iface, uint length)
{
  printf("NAT ICMP\n");
  sr_ip_hdr_t *ip = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t8_hdr_t *icmp = (sr_icmp_t8_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  char *matched_iface = sr_lpm(sr, ip->ip_dst);

  if (matched_iface && (strcmp(iface, "eth1") == 0) && (strcmp(matched_iface, "eth2") == 0)) {
    printf("ICMP Internal -> External\n");
    
    struct sr_nat_mapping* mapping = sr_nat_lookup_internal(sr->nat, ip->ip_src, icmp->identifier, nat_mapping_icmp);
    if (mapping) {
      printf("ICMP Internal Mapping Found\n");
      ip->ip_src = sr->nat->external_ip;
      icmp->identifier = mapping->aux_ext;
      icmp->icmp_sum = 0;
      icmp->icmp_sum = cksum((void *)icmp, ntohs(ip->ip_len) - sizeof(sr_ip_hdr_t));

      ip->ip_sum = 0;
      ip->ip_sum = cksum((void *)ip, sizeof(sr_ip_hdr_t));

      return 0;
    } else {
      printf("ICMP Internal Mapping Not Found\n");
      struct sr_nat_mapping *new_mapping = sr_nat_insert_mapping(sr->nat, ip->ip_src, icmp->identifier, nat_mapping_icmp);
      ip->ip_src = sr->nat->external_ip;
      icmp->identifier = new_mapping->aux_ext;

      icmp->icmp_sum = 0;
      icmp->icmp_sum = cksum((void *)icmp, ntohs(ip->ip_len) - sizeof(sr_ip_hdr_t));

      ip->ip_sum = 0;
      ip->ip_sum = cksum((void *)ip, sizeof(sr_ip_hdr_t));
      return 0;
    }
  } else if(strcmp(iface, "eth2") == 0) {
    printf("ICMP External -> Internal\n");
    struct sr_nat_mapping* mapping = sr_nat_lookup_external(sr->nat, icmp->identifier, nat_mapping_icmp);
    if (mapping) {
      ip->ip_dst = mapping->ip_int;
      icmp->identifier = mapping->aux_int;

      icmp->icmp_sum = 0;
      icmp->icmp_sum = cksum((void *)icmp, ntohs(ip->ip_len) - sizeof(sr_ip_hdr_t));

      ip->ip_sum = 0;
      ip->ip_sum = cksum((void *)ip, sizeof(sr_ip_hdr_t));
      return 0;
    }else {
      return -1;
    }
  }
  return 0;
}

uint16_t tcp_cksum(uint8_t *packet, uint tcp_length)
{
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  unsigned int total_length = tcp_length + sizeof(sr_tcp_pseudo_hdr_t);

  uint8_t *pseudo = (uint8_t *)malloc(total_length);
  sr_tcp_pseudo_hdr_t *pseudo_hdr = (sr_tcp_pseudo_hdr_t *)pseudo;

  pseudo_hdr->ip_src = ip_header->ip_src;
  pseudo_hdr->ip_dst = ip_header->ip_dst;
  pseudo_hdr->reserved = 0;
  pseudo_hdr->ip_p = ip_header->ip_p;
  pseudo_hdr->len = htons(tcp_length);

  memcpy(pseudo + sizeof(sr_tcp_pseudo_hdr_t), tcp_hdr, tcp_length);

  return cksum((void *)pseudo, total_length);
}

void send_icmp_unsol(struct sr_instance *sr, uint8_t *packet, int type, int code, uint length, char *iface) {
  printf("Sending ICMP type:%d code:%d\n", type, code);
  sr_ethernet_hdr_t *ethernet = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  uint len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *new_packet = (uint8_t *) malloc(len);

  sr_ethernet_hdr_t *new_ethernet = (sr_ethernet_hdr_t *) new_packet;
  sr_ip_hdr_t *new_ip = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *new_icmp = (sr_icmp_t3_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  new_ip->ip_hl = ip->ip_hl;
  new_ip->ip_v = ip->ip_v;
  new_ip->ip_tos = ip->ip_tos;
  new_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip->ip_id = ip->ip_id;
  new_ip->ip_off = ip->ip_off;
  new_ip->ip_ttl = IP_TTL;
  new_ip->ip_p = 1;
  new_ip->ip_sum = 0;
  new_ip->ip_dst = ip->ip_src;

  char* matched_name = sr_lpm(sr, ip->ip_src);
  if (!matched_name) {
    return;
  }
  struct sr_if *matched_interface = sr_get_interface(sr, matched_name);
  new_ip->ip_src = matched_interface->ip;
  if (type == 3 && code == 3) {
    new_ip->ip_src = ip->ip_dst;
  }
  new_ip->ip_sum = cksum((void *)new_ip, sizeof(sr_ip_hdr_t));

  new_icmp->icmp_type = type;
  new_icmp->icmp_code = code;
  new_icmp->icmp_sum = 0;
  new_icmp->unused = 0;
  new_icmp->next_mtu = 0;
  memcpy(new_icmp->data, ip, ICMP_DATA_SIZE);
  new_icmp->icmp_sum = cksum((void *) new_icmp, sizeof(sr_icmp_t3_hdr_t));

  new_ethernet->ether_type = ntohs(ethertype_ip);
  memcpy(new_ethernet->ether_shost, matched_interface->addr, ETHER_ADDR_LEN);
  memcpy(new_ethernet->ether_dhost, ethernet->ether_shost, ETHER_ADDR_LEN);

  sr_send_packet(sr, (uint8_t*)new_packet, len, matched_name);
}

void print_mapping(struct sr_nat_mapping *mapping)
{
  printf("Printing Mappings:\n");

  if (mapping == NULL)
  {
    printf("null\n");
    return;
  }

  while (mapping != NULL)
  {
    printf("ip_int: %d\n", mapping->ip_int);
    printf("ip_ext: %d\n", mapping->ip_ext);
    printf("aux_int: %d\n", mapping->aux_int);
    printf("aux_ext: %d\n", mapping->aux_ext);
    if (mapping->next == NULL) 
    {
      printf("next: NULL\n");
    }
    else
    {
      printf("next: %p\n", (void *)mapping->next);
    }
    mapping = mapping->next;
  }
}

int nat_received_tcp(struct sr_instance *sr, uint8_t *packet, char *iface, uint length)
{
  printf("NAT TCP\n");
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  char* matched_dest = sr_lpm(sr, ip->ip_dst);
  int is_unsolicited = is_syn(packet);

  if (matched_dest && (strcmp(iface, "eth1") == 0) && (strcmp(matched_dest, "eth2") == 0)) {
    printf("TCP Internal -> External\n");
    struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat, ip->ip_src, ntohs(tcp->port_src), nat_mapping_tcp);

    if (mapping) {
      printf("TCP Internal Mapping Found\n");
      ip->ip_src = sr->nat->external_ip;
      tcp->port_src = htons(mapping->aux_ext);

      tcp->checksum = 0;
      tcp->checksum = tcp_cksum(packet, length - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t));

      ip->ip_sum = 0;
      ip->ip_sum = cksum((void *)ip, sizeof(sr_ip_hdr_t));

      return 0;
    } else {
      struct sr_nat_mapping *new_mapping = sr_nat_insert_mapping(sr->nat, ip->ip_src, ntohs(tcp->port_src), nat_mapping_tcp);
      ip->ip_src = sr->nat->external_ip;
      
      print_mapping(sr->nat->mappings);
      tcp->port_src = htons(new_mapping->aux_ext);
      tcp->checksum = 0;
      tcp->checksum = tcp_cksum(packet, length - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t));

      ip->ip_sum = 0;
      ip->ip_sum = cksum((void *)ip, sizeof(sr_ip_hdr_t));
      printf("Returning TCP\n");
      return 0;
    }
  } else if(strcmp(iface, "eth2") == 0) {
    printf("TCP External -> Internal\n");
    struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, ntohs(tcp->port_dst), nat_mapping_tcp);

    if (mapping) {
      ip->ip_dst = mapping->ip_int;
      tcp->port_dst = htons(mapping->aux_int);

      tcp->checksum = 0;
      tcp->checksum = tcp_cksum(packet, length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

      ip->ip_sum = 0;
      ip->ip_sum = cksum((void *)ip, sizeof(sr_ip_hdr_t));
      printf("Returned TCP\n");
      return 0;
    } else {
      pthread_mutex_lock(&sr->nat->lock);

      if (is_unsolicited)
      {
        if (tcp->port_dst >= 1024) {
          waiting_unsol_t *new_unsol = (waiting_unsol_t *)malloc(sizeof(waiting_unsol_t));
          new_unsol->sr = sr;
          new_unsol->packet = packet;
          new_unsol->packet_len = length;
          memcpy(new_unsol->iface, iface, 4);
          new_unsol->waited = 0;
          new_unsol->next = NULL;

          waiting_unsol_t *curr = sr->nat->waiting_unsol;
          if (!curr){
            sr->nat->waiting_unsol = new_unsol;
          } else {
            while (curr->next)
            {
              curr = curr->next;
            }
            curr->next = new_unsol;
          }
          pthread_mutex_unlock(&sr->nat->lock);
          return -1;
        } else if (tcp->port_dst == 22) {
          pthread_mutex_unlock(&sr->nat->lock);
          return 0;
        }
      }
      pthread_mutex_unlock(&sr->nat->lock);
    }
  }
  return 0;
}
