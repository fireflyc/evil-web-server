#ifndef EVIL_WEB_SERVER_PACKET_H
#define EVIL_WEB_SERVER_PACKET_H

#include <libnet.h>
#include <math.h>
#include "common.h"

int response_arp(web_server_t *web_server, struct libnet_ethernet_hdr *eth_hdr, struct libnet_ipv4_hdr *ip_hdr,
                 char *errbuf);

int response_packet1(uint ack, uint seq, uint16_t ipid, const char *response, uint16_t response_size, uint8_t control,
                     struct libnet_tcp_hdr *tcp_hdr, struct libnet_ipv4_hdr *ip_hdr, char *errbuf);

#endif //EVIL_WEB_SERVER_PACKET_H
