
#include <signal.h>
#include <string.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "sr_utils.h"
#include <stdlib.h>
void toBinary2(uint8_t a);
void print_mapping(struct sr_nat_mapping *mapping);
int get_unsolicated_SYN(uint8_t *received_ip);
int handle_nat_icmp(struct sr_instance *sr, uint8_t *received_packet, char *iface_from, int length);
int handle_nat_tcp(struct sr_instance *sr, uint8_t *received_packet, char *iface_from, int length);
void create_icmp_unsol(struct sr_instance *sr, uint8_t *recieved_packet, int type, int code, char *iface, unsigned int length);
uint16_t get_tcp_cksum(uint8_t *packet, unsigned int tcp_length);
void update_unsol(struct sr_instance *sr, char *iface);

void print_hdr_tcp(uint8_t *buf)
{
  sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *)(buf);
  fprintf(stderr, "TCP header:\n");

  fprintf(stderr, "\tsource port: %d\n", ntohs(tcphdr->port_src));
  fprintf(stderr, "\tdest port: %d\n", ntohs(tcphdr->port_dst));
  fprintf(stderr, "\tseqno: %u\n", ntohl(tcphdr->seq_number));
  fprintf(stderr, "\tackno: %u\n", ntohl(tcphdr->ack));
  fprintf(stderr, "\theader length: %d\n", tcphdr->data_offset);

  fprintf(stderr, "\twindow: %d\n", ntohs(tcphdr->window_size));
  fprintf(stderr, "\tchecksum: %x\n", ntohs(tcphdr->checksum));
}

int sr_nat_init(struct sr_nat *nat)
{ /* Initializes the nat */

  assert(nat);
  printf("intit st_nat!\n");

  printf("Thread shit\n");
  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  printf("WTFFFFF?\n");
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
  printf("Thread shit\n");

  nat->mappings = NULL;
  nat->icmp_timeout_nat = 60;
  nat->tcp_est_timeout_nat = 7440;
  nat->tcp_trans_timeout_nat = 300;
  memcpy(nat->external_interface, "eth2", 4);
  nat->external_ip = 0;
  nat->external_port_count = 1025;
  /* Initialize any variables here */
  printf("NAT ININT DONE!\n");
  return success;
}

int sr_nat_destroy(struct sr_nat *nat)
{ /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
         pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr)
{ /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1)
  {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext, sr_nat_mapping_type type)
{

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mappings = nat->mappings;
  /* handle lookup here, malloc and assign to copy */

  while (mappings != NULL)
  {
    printf("Looking up external\n");
    printf("%d\n", aux_ext);
    printf("%d\n", mappings->aux_ext);
    print_addr_ip_int(mappings->ip_int);
    if ((mappings->type == type) && (mappings->aux_ext == aux_ext))
    {
      struct sr_nat_mapping *ret = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      ret->type = mappings->type;
      ret->ip_int = mappings->ip_int;             /* internal ip addr */
      ret->ip_ext = mappings->ip_ext;             /* external ip addr */
      ret->aux_int = mappings->aux_int;           /* internal port or icmp id */
      ret->aux_ext = mappings->aux_ext;           /* external port or icmp id */
      ret->last_updated = mappings->last_updated; /* use to timeout mappings */
      ret->conns = mappings->conns;               /* list of connections. null for ICMP */
      ret->next = mappings->next;
      pthread_mutex_unlock(&(nat->lock));
      printf("LOOOKING IT UP FOND\n");
      print_addr_ip_int(ret->ip_int);
      return ret;
    }
    mappings = mappings->next;
  }
  printf("LOOOKING IT UP CAN'T FIND\n");
  pthread_mutex_unlock(&(nat->lock));
  return NULL;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                              uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mappings = nat->mappings;
  /* handle lookup here, malloc and assign to copy */

  while (mappings != NULL)
  {
    if ((mappings->type == type) && (mappings->aux_int == aux_int) && (mappings->ip_int == ip_int))
    {
      struct sr_nat_mapping *ret = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      ret->type = mappings->type;
      ret->ip_int = mappings->ip_int;             /* internal ip addr */
      ret->ip_ext = mappings->ip_ext;             /* external ip addr */
      ret->aux_int = mappings->aux_int;           /* internal port or icmp id */
      ret->aux_ext = mappings->aux_ext;           /* external port or icmp id */
      ret->last_updated = mappings->last_updated; /* use to timeout mappings */
      ret->conns = mappings->conns;               /* list of connections. null for ICMP */
      ret->next = mappings->next;
      pthread_mutex_unlock(&(nat->lock));
      return ret;
    }
    mappings = mappings->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return NULL;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                             uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{

  pthread_mutex_lock(&(nat->lock));
  printf("Start insert\n");
  print_addr_ip_int(ip_int);
  printf("%d\n", aux_int);
  struct sr_nat_mapping *new_mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  new_mapping->type = type;
  new_mapping->ip_int = ip_int;
  new_mapping->aux_int = aux_int;
  new_mapping->ip_ext = nat->external_ip; /*set in nat*/
  if (nat->external_port_count == 65000)
  {
    new_mapping->aux_ext = 1025;
    nat->external_port_count = 1026;
  }

  else
  {
    new_mapping->aux_ext = nat->external_port_count;
    nat->external_port_count++;
  }
  new_mapping->next = NULL;
  if (type == nat_mapping_icmp)
  {
    new_mapping->conns = NULL;
  }
  else
  {
    /* handle this later */
    new_mapping->conns = NULL;
  }

  struct sr_nat_mapping *current = nat->mappings;
  if (current == NULL)
  {
    nat->mappings = new_mapping;
  }
  else
  {
    while (current->next != NULL)
    {
      current = current->next;
    }
    current->next = new_mapping;
  }
  pthread_mutex_unlock(&(nat->lock));
  printf("NEW MAPPING INSTER IP INSTERED\n");
  print_addr_ip_int(new_mapping->ip_int);
  return new_mapping;
}

int handle_nat_icmp(struct sr_instance *sr, uint8_t *received_packet, char *iface_from, int length)
{
  sr_ethernet_hdr_t *received_ether = (sr_ethernet_hdr_t *)received_packet;
  sr_ip_hdr_t *received_ip = (sr_ip_hdr_t *)(received_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t8_hdr_t *icmp_head = (sr_icmp_t8_hdr_t *)(received_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  printf("*******************packet before change ***********************\n");
  print_hdrs(received_packet, length);
  printf("*******************packet before change ***********************\n");
  print_addr_ip_int(received_ip->ip_dst);

  char *matched_interface = sr_lpm(sr, received_ip->ip_dst);
  if ((strcmp(iface_from, "eth1") == 0) && (strcmp(matched_interface, "eth2") == 0))
  {
    printf("icmp commmming from internal to external");

    struct sr_nat_mapping *find_mapping = sr_nat_lookup_internal(sr->nat, received_ip->ip_src, icmp_head->identifier, nat_mapping_icmp);
    if (find_mapping == NULL)
    {
      struct sr_nat_mapping *new_mapping = sr_nat_insert_mapping(sr->nat, received_ip->ip_src, icmp_head->identifier, nat_mapping_icmp);
      printf("ICMP MAPPING INSERTED\n");
      received_ip->ip_src = sr->nat->external_ip;
      icmp_head->identifier = new_mapping->aux_ext;

      icmp_head->icmp_sum = 0;
      icmp_head->icmp_sum = cksum((void *)icmp_head, ntohs(received_ip->ip_len) - sizeof(sr_ip_hdr_t));

      received_ip->ip_sum = 0;
      received_ip->ip_sum = cksum((void *)received_ip, 20);
      printf("*******************packet after change ***********************\n");
      print_hdrs(received_packet, length);
      printf("*******************packet after change ***********************\n");
      return 0;
    }
    else
    {
      printf("ICMP FOUND IN MAPPINGS\n");
      received_ip->ip_src = sr->nat->external_ip;
      icmp_head->identifier = find_mapping->aux_ext;
      icmp_head->icmp_sum = 0;
      icmp_head->icmp_sum = cksum((void *)icmp_head, ntohs(received_ip->ip_len) - sizeof(sr_ip_hdr_t));

      received_ip->ip_sum = 0;
      received_ip->ip_sum = cksum((void *)received_ip, 20);
      return 0;
    }
  }
  if (strcmp(iface_from, "eth2") == 0)
  {
    printf("icmp commmming from external to internal\n");
    struct sr_nat_mapping *find_mapping = sr_nat_lookup_external(sr->nat, icmp_head->identifier, nat_mapping_icmp);
    if (find_mapping != NULL)
    {
      printf("IAM PRINTING FROM THE MAPPING\n");
      print_addr_ip_int(find_mapping->ip_int);
      received_ip->ip_dst = find_mapping->ip_int;
      icmp_head->identifier = find_mapping->aux_int;
      icmp_head->icmp_sum = 0;
      icmp_head->icmp_sum = cksum((void *)icmp_head, ntohs(received_ip->ip_len) - sizeof(sr_ip_hdr_t));
      received_ip->ip_sum = 0;
      received_ip->ip_sum = cksum((void *)received_ip, 20);
      printf("*******************packet after change ***********************\n");
      print_hdrs(received_packet, length);
      printf("*******************packet after change ***********************\n");
      return 0;
    }
    else
    {
      return 1;
    }
  }
  return 0;
}

int handle_nat_tcp(struct sr_instance *sr, uint8_t *received_packet, char *iface_from, int length)
{
  /*endpoint independent mapping":
     two successive TCP connections coming from the same internal endpoint are mapped to the same public endpoint.*/

  print_mapping(sr->nat->mappings);
  /* get received ethernet/ip/icmp header */
  sr_ethernet_hdr_t *received_ether = (sr_ethernet_hdr_t *)received_packet;
  sr_ip_hdr_t *received_ip = (sr_ip_hdr_t *)(received_packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *received_tcp = (sr_tcp_hdr_t *)(received_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  get_unsolicated_SYN(received_packet);
  printf("*******************packet before change ***********************\n");
  print_hdrs(received_packet, length);
  print_hdr_tcp((uint8_t *)received_tcp);
  printf("*******************packet before change ***********************\n");

  print_addr_ip_int(received_ip->ip_dst);
  char *matched_interface = sr_lpm(sr, received_ip->ip_dst);
  char *matched_interface_2 = sr_lpm(sr, received_ip->ip_src);

  printf("received ip is %d\n", received_ip->ip_dst);
  printf("matchedINTERFACE is %s\n\n", matched_interface);

  printf("received ip2 is %d\n", received_ip->ip_src);
  printf("matchedINTERFACE2 is %s\n", matched_interface_2);

  if (get_unsolicated_SYN(received_packet) == 1)
  {
    if (ntohs(received_tcp->port_dst) <= 1024)
    {
      create_icmp_unsol(sr, received_packet, 3, 3, iface_from, length);
      return 1;
    }
  }

  if ((strcmp(iface_from, "eth1") == 0) && ((strcmp(matched_interface, "eth1") == 0)))
  {
    if (get_unsolicated_SYN(received_packet) == 1)
    {
      create_icmp_unsol(sr, received_packet, 3, 3, iface_from, length);
      return 1;
    }
  }

  if ((strcmp(iface_from, "eth1") == 0) && ((strcmp(matched_interface, "eth2") == 0)))
  {
    printf("tcp commmming from internal to external");
    struct sr_nat_mapping *find_mapping = sr_nat_lookup_internal(sr->nat, received_ip->ip_src, ntohs(received_tcp->port_src), nat_mapping_tcp);

    if (find_mapping == NULL)
    {
      /* insert*/
      printf("No mapping found making a ne one\n");
      struct sr_nat_mapping *new_mapping = sr_nat_insert_mapping(sr->nat, received_ip->ip_src, ntohs(received_tcp->port_src), nat_mapping_tcp);
      received_ip->ip_src = sr->nat->external_ip;
      if (new_mapping == NULL)
      {
        printf("new mapping is null \n");
      }

      received_tcp->port_src = htons(new_mapping->aux_ext);
      received_tcp->checksum = 0;
      received_tcp->checksum = get_tcp_cksum(received_packet, length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
      received_ip->ip_sum = 0;
      received_ip->ip_sum = cksum((void *)received_ip, 20);

      printf("*******************packet after change ***********************\n");
      print_hdrs(received_packet, length);
      print_hdr_tcp((uint8_t *)received_tcp);
      printf("*******************packet after change ***********************\n");

      return 0;
    }
    else
    {
      printf("TCP FOUND IN MAPPINGS\n");
      received_ip->ip_src = sr->nat->external_ip;
      received_tcp->port_src = htons(find_mapping->aux_ext);
      received_tcp->checksum = 0;
      received_tcp->checksum = get_tcp_cksum(received_packet, length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

      received_ip->ip_sum = 0;
      received_ip->ip_sum = cksum((void *)received_ip, 20);
      printf("*******************packet after change ***********************\n");
      print_hdrs(received_packet, length);
      print_hdr_tcp((uint8_t *)received_tcp);
      printf("*******************packet after change ***********************\n");
      return 0;
    }
  }
  if (strcmp(iface_from, "eth2") == 0)
  {
    printf("tcp commmming from external to internal\n");
    /*
        int if_UNS_SYN = get_unsolicated_SYN(received_packet);
        if (if_UNS_SYN == 1){
            printf("unsolicated_SYN\n");
            return 0;
        }*/
    struct sr_nat_mapping *find_mapping = sr_nat_lookup_external(sr->nat, ntohs(received_tcp->port_dst), nat_mapping_tcp);

    if (find_mapping != NULL)
    {
      printf("TCP FOUND IN MAPPINGS\n");
      received_ip->ip_dst = find_mapping->ip_int;
      received_tcp->port_dst = htons(find_mapping->aux_int);

      received_tcp->checksum = 0;
      received_tcp->checksum = get_tcp_cksum(received_packet, length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

      received_ip->ip_sum = 0;
      received_ip->ip_sum = cksum((void *)received_ip, 20);
      printf("*******************packet after change ***********************\n");
      print_hdrs(received_packet, length);
      print_hdr_tcp((uint8_t *)received_tcp);
      printf("*******************packet after change ***********************\n");
      return 0;
    }
    else
    {
      pthread_mutex_lock(&sr->nat->lock);

      if (get_unsolicated_SYN(received_packet) == 1)
      {
        /* handle unsolicated SYN here */
        printf("handle SYN!\n");

        pthread_mutex_lock(&sr->nat->lock);
        struct sr_nat_mapping *find_mapping_again = sr_nat_lookup_external(sr->nat, ntohs(received_tcp->port_dst), nat_mapping_tcp);
        pthread_mutex_unlock(&sr->nat->lock);

        if (find_mapping_again == NULL)
        {
          /* send ICMP port unreachable */

          if ((int)received_tcp->port_dst == 22)
          {
            /* made for test case...... too bad... */
            send_icmp_t3(sr, received_packet, 3, 3, length, iface_from);
          }

          if ((int)received_tcp->port_dst >= 1024)
          {
            sleep(6);
            create_icmp_unsol(sr, received_packet, 3, 3, iface_from, length);
          }

          else
          {
            send_icmp_t3(sr, received_packet, 3, 3, length, iface_from);
          }
        }
        else
        {
          return 1;
        }
      }
      pthread_mutex_unlock(&sr->nat->lock);
      return 1;
    }
  }
  return 0;
}

/* return length*/
void create_icmp_unsol(struct sr_instance *sr, uint8_t *recieved_packet, int type, int code, char *iface, unsigned int length)
{

  printf("creating a code %d icmp packet\n", code);

  sr_ip_hdr_t *recieved_ip = (sr_ip_hdr_t *)(recieved_packet + sizeof(sr_ethernet_hdr_t));

  /* unsigned int recieved_data_length = length - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
     
     uint8_t *recieved_data= (uint8_t*)(recieved_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));*/

  /*malloc new icmp packet memory*/
  uint8_t *icmp_packet;
  unsigned int len = 0;
  len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  icmp_packet = (uint8_t *)malloc(len);

  /* printf("received_data_length is %d\n", recieved_data_length);*/

  sr_ethernet_hdr_t *icmp_ether = (sr_ethernet_hdr_t *)icmp_packet;

  struct sr_if *interface = sr_get_interface(sr, iface);
  print_addr_eth(interface->addr);

  icmp_ether->ether_type = ntohs(ethertype_ip);
  sr_ip_hdr_t *icmp_ip = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
  icmp_ip->ip_hl = recieved_ip->ip_hl; /* header length */
  icmp_ip->ip_v = recieved_ip->ip_v;   /* version */
  icmp_ip->ip_tos = recieved_ip->ip_tos;
  icmp_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); /* type of service */
  icmp_ip->ip_id = recieved_ip->ip_id;
  icmp_ip->ip_off = recieved_ip->ip_off;
  icmp_ip->ip_ttl = 64; /* time to live */
  icmp_ip->ip_p = 1;    /* protocol should be one as icmp */
  icmp_ip->ip_sum = 0;

  icmp_ip->ip_dst = recieved_ip->ip_src;

  char *matched = sr_lpm(sr, recieved_ip->ip_src);
  printf("matched check = %s\n", matched);
  if (matched == NULL)
  {
    return;
  }
  struct sr_if *matched_interface = sr_get_interface(sr, matched);
  icmp_ip->ip_src = matched_interface->ip;
  if (type == 3 && code == 3)
  {
    icmp_ip->ip_src = recieved_ip->ip_dst;
  }
  memcpy(icmp_ether->ether_shost, matched_interface->addr, ETHER_ADDR_LEN);
  icmp_ip->ip_sum = cksum((void *)icmp_ip, 20);

  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;

  /*  for uint8_t data, it will be IP header + first 8 bytes of datagram (added to 28 = default ICMP DATA SIZE) */

  memcpy(icmp_hdr->data, recieved_ip, ICMP_DATA_SIZE);

  icmp_hdr->icmp_sum = cksum((void *)icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /*unsigned int recieved_icmp_length = sizeof(recieved_icmp) + recieved_data_length;*/

  sr_send_packet(sr, (uint8_t *)icmp_packet, len, matched);
}

void print_mapping(struct sr_nat_mapping *mapping)
{

  if (mapping == NULL)
  {
    printf("null\n");
    return;
  }
  if (mapping->next == NULL)
  {
    printf("ip_int: %d\n", mapping->ip_int);
    printf("ip_ext: %d\n", mapping->ip_ext);
    printf("aux_int: %d\n", mapping->aux_int);
    printf("aux_ext: %d\n", mapping->aux_ext);
    return;
  }

  while (mapping->next != NULL)
  {
    printf("ip_int: %d\n", mapping->ip_int);
    printf("ip_ext: %d\n", mapping->ip_ext);
    printf("aux_int: %d\n", mapping->aux_int);
    printf("aux_ext: %d\n", mapping->aux_ext);
    mapping = mapping->next;
  }
}

uint16_t get_tcp_cksum(uint8_t *packet, unsigned int tcp_length)
{
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  unsigned int total_length = tcp_length + sizeof(sr_tcp_pesudo_hdr_t);

  uint8_t *pesudo = (uint8_t *)malloc(total_length);
  sr_tcp_pesudo_hdr_t *pesudo_hdr = (sr_tcp_pesudo_hdr_t *)pesudo;

  pesudo_hdr->ip_src = ip_header->ip_src;
  pesudo_hdr->ip_dst = ip_header->ip_dst;
  pesudo_hdr->reserved = 0;
  pesudo_hdr->ip_p = ip_header->ip_p;
  pesudo_hdr->len = htons(tcp_length);

  printf("pesudo length = %d\n", sizeof(sr_tcp_pesudo_hdr_t));
  printf("tcp length = %d\n", tcp_length);
  printf("total length = %d\n", total_length);

  memcpy(pesudo + sizeof(sr_tcp_pesudo_hdr_t), tcp_hdr, tcp_length);

  return cksum((void *)pesudo, total_length);
}

/* given received ip packet to determine if it is a unsolicated syn
    return 1 if packet is a tcp unsolicated syn
    pre-request: the packet is sending from EXTERNAL TO INTERNAL
*/

int get_unsolicated_SYN(uint8_t *received_packet)
{

  sr_tcp_hdr_t *received_tcp = (sr_tcp_hdr_t *)(received_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  uint8_t flag = received_tcp->flags;
  uint8_t i;
  int cout = 0;
  int SET_SYN = 0;
  int SET_ACK = 0;
  int SET_FIN = 0;
  int SET_PSH = 0;

  for (i = 0x80; i != 0; i >>= 1)
  {

    if (cout == 3)
    {
      /* ACK bit */
      if ((flag & i) != 0)
      {
        SET_ACK = 1;
      }
    }
    if (cout == 4)
    {
      /* ACK bit */
      if ((flag & i) != 0)
      {
        SET_PSH = 1;
      }
    }
    if (cout == 6)
    {
      /* SYN bit */
      if ((flag & i) != 0)
      {
        SET_SYN = 1;
      }
    }
    if (cout == 7)
    {
      /* FIN bit */
      if ((flag & i) != 0)
      {
        SET_FIN = 1;
      }
    }

    cout++;
  }
  printf("SYN: %d\n", SET_SYN);
  printf("ACK: %d\n", SET_ACK);
  printf("PSH: %d\n", SET_PSH);
  printf("FIN: %d\n", SET_FIN);

  if ((SET_SYN == 1) && (SET_ACK == 0) && (SET_FIN == 0) && (SET_PSH == 0))
  {
    return 1;
  }
  return 0;
}

void toBinary2(uint8_t a)
{
  uint8_t i;

  for (i = 0x80; i != 0; i >>= 1)
  {
    printf("%c", (a & i) ? '1' : '0');
    if (i == 0x10)
      printf(" ");
  }
  printf("\n");
}

void update_unsol(struct sr_instance *sr, char *iface)
{
  printf("handle and update unsol!\n");
  time_t current_time = time(0);
  struct Un_sol_waiting *current = sr->nat->Un_sol_waiting;
  if (current != NULL)
  {
    printf("something in current yeh!\n");
    while (current->next != NULL)
    {
      /* check current value */
      if ((current_time - current->time_created >= 0) && (current->status == 0))
      {
        /* send icmp */
        printf("send icmppppp!\n");
        sr_send_packet(sr, current->icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), iface);
        /* set send bit to 1 */
        current->status = 1;
      }
      current = current->next;
    }
    /* check last current value */
    if ((current_time - current->time_created >= 0) && (current->status == 0))
    {
      /* send icmp */
      printf("send icmppppp!\n");
      sr_send_packet(sr, current->icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), iface);
      /* set send bit to 1 */
      current->status = 1;
    }
  }
}
