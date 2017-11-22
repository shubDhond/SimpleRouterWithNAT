#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

void send_icmp_t3(struct sr_instance* sr, uint8_t* packet, int type, int code, uint len, char* iface) {
    printf("Sending icmp packet type: %d and code: %d\n", type, code);
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

    /* New ICMP packet */
    uint8_t* icmp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    sr_ethernet_hdr_t *icmp_ether = (sr_ethernet_hdr_t *) icmp;
    sr_ip_hdr_t *icmp_ip = (sr_ip_hdr_t *) (icmp + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*) (icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    char* mac = sr_lpm(sr, ip_header->ip_src);
    if (mac == NULL) {
        return;
    }
    printf("Found MAC\n");
    struct sr_if* mac_interface = sr_get_interface(sr, mac);
    if (!mac_interface) {
        return;
    }
    icmp_ip->ip_src = mac_interface->ip;
    if (type == 3 && code == 3) {
        icmp_ip->ip_src = ip_header->ip_dst;
    }

    /* Ethernet header */
    icmp_ether->ether_type = ntohs(ethertype_ip);

    /* IP header */
    icmp_ip->ip_hl = ip_header->ip_hl;
    icmp_ip->ip_v = ip_header->ip_v;
    icmp_ip->ip_tos = ip_header->ip_tos;
    icmp_ip->ip_len = htons( sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    icmp_ip->ip_id = ip_header->ip_id;
    icmp_ip->ip_off = ip_header->ip_off;
    icmp_ip->ip_ttl = IP_TTL;
    icmp_ip->ip_p = ip_protocol_icmp;
    icmp_ip->ip_sum = 0;
    icmp_ip->ip_dst = ip_header->ip_src;
    memcpy(icmp_ether->ether_shost, mac_interface->addr, ETHER_ADDR_LEN);
    icmp_ip->ip_sum = cksum((void*)icmp_ip, sizeof(sr_ip_hdr_t));

    /* ICMP Header */
    icmp_header->icmp_type = type;
    icmp_header->icmp_code = code;
    icmp_header->icmp_sum = 0;
    icmp_header->unused = 0;
    icmp_header->next_mtu = 0;
    memcpy(icmp_header->data, ip_header, ICMP_DATA_SIZE);
    icmp_header->icmp_sum = cksum((void*) icmp_header, sizeof(sr_icmp_t3_hdr_t));
    uint length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, icmp_ip->ip_dst);
    if (entry) {
        printf("ARP Cache Hit\n");
        memcpy(icmp_ether->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(icmp_ether->ether_shost, mac_interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, (uint8_t*) icmp, length, mac);
        free(entry);
    } else {
        printf("ARP Cache Miss\n");
        memcpy(icmp_ether->ether_shost, mac_interface->addr, ETHER_ADDR_LEN);
        sr_arpcache_queuereq(&sr->cache, icmp_ip->ip_dst, icmp, length, mac);
    }
    free(icmp);
}

void send_host_unreachable(struct sr_instance* sr, struct sr_arpreq* req) {
    struct sr_packet* packet;
    for (packet = req->packets; packet != NULL; packet=packet->next) {
        sr_ip_hdr_t* ip_h = (sr_ip_hdr_t*) (packet->buf + sizeof(sr_ethernet_hdr_t));
        char* iface = sr_lpm(sr, ip_h->ip_src);
        send_icmp_t3(sr, packet->buf, 3, 1, packet->len, iface);
    }
}

void send_arp_request(struct sr_instance* sr, struct sr_arpreq* req) {
    uint8_t* arp_packet = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    /* Ethernet header */
    sr_ethernet_hdr_t* arp_ether = (sr_ethernet_hdr_t*) arp_packet;
    struct sr_if* interface = sr_get_interface(sr, req->packets->iface);
    memcpy(arp_ether->ether_shost, interface->addr, ETHER_ADDR_LEN);
    memset(arp_ether->ether_dhost, 255, ETHER_ADDR_LEN);
    arp_ether->ether_type = htons(ethertype_arp);

    /* ARP header */
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (arp_packet + sizeof(sr_ethernet_hdr_t));
    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_pro = htons(2048);
    arp_header->ar_hln = ETHER_ADDR_LEN;
    arp_header->ar_pln = 4;
    arp_header->ar_op = htons(arp_op_request);
    memcpy(arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN);
    arp_header->ar_sip = interface->ip;
    memset(arp_header->ar_tha, 0, ETHER_ADDR_LEN);
    arp_header->ar_tip = req->ip;

    uint8_t size = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
    print_hdrs(arp_packet, size);
    int error = sr_send_packet(sr, arp_packet, size, interface->name);
    if (!error) {
        printf("ARP request packet sent\n");
    } else {
        printf("ARP request send failed\n");
    }
    free(arp_packet);
} 


void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req) {
    time_t now = time(0);
    if (difftime(now, req->sent) >= 1.0) {
        if (req->times_sent >= 5){
            printf("ICMP unreachable\n");
            send_host_unreachable(sr, req);
            sr_arpreq_destroy(&sr->cache, req);
        } else {
            printf("Sending new ARP request\n");
            send_arp_request(sr, req);
            req->sent = now;
            req->times_sent++;
        }
    }
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpcache* cache = &sr->cache;
    struct sr_arpreq* req;
    for (req = cache->requests; req != NULL; req = req->next) {
        handle_arpreq(sr, req);
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

