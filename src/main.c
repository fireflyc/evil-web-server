#include <pcap.h>
#include <stdlib.h>
#include <libnet.h>
#include "common.h"
#include "packet.h"

#ifdef SIOCGIFHWADDR
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#else

#include <ifaddrs.h>
#include <net/if_dl.h>

#endif

#define FALSE (0==1)
#define TRUE (1==1)

void on_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    web_server_t *web_server = (web_server_t *) arg;
    uint ethernet_size = LIBNET_ETH_H;
    struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *) (packet + ethernet_size);
    char errbuf[BUFSIZ];

    struct libnet_ethernet_hdr *ether_hdr = (struct libnet_ethernet_hdr *) packet;
    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
        struct libnet_arp_hdr *arp_hdr = (struct libnet_arp_hdr *) (packet + LIBNET_ETH_H);
        if (ntohs(arp_hdr->ar_op) == ARPOP_REQUEST) {
            log_info("received arp query\n");
            //收到ARP
            response_arp(web_server, ether_hdr, ip_hdr, errbuf);
            log_info("send response\n");
        }
        return;
    }

    uint ip_size = (uint) ip_hdr->ip_hl * 4;
    if (ip_size < 20) {
        return;
    }
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return;
    }
    //确定是TCP数据包
    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *) (packet + ethernet_size + ip_size);
    uint tcp_size = (uint) (tcp_hdr->th_off * 4);
    if (tcp_size < 20) {
        return;
    }
    if (ntohs(tcp_hdr->th_dport) != 81) {
        return;
    }
    log_info("received request\n");
    uint payload_size = (uint) (ntohs(ip_hdr->ip_len) - (ip_size + tcp_size));
    if (payload_size == 0) {
        //不打开socket就需要在这里伪造三次握手
        if (tcp_hdr->th_flags == TH_SYN) {
            //握手数据包
            uint ack = ntohl(tcp_hdr->th_seq) + payload_size;
            uint32_t seq = libnet_get_prand(LIBNET_PRu32);
            response_packet1(ack + 1, seq, web_server->ipid++, NULL, 0, TH_ACK | TH_SYN, tcp_hdr, ip_hdr, errbuf);
            return;
        }
    }
    log_info("received request url\n");
    if (payload_size < 3) {
        return;
    }
    u_char *payload = (u_char *) (packet + ethernet_size + ip_size + tcp_size);
    if (*payload != 'G' || *(payload + 1) != 'E' || *(payload + 2) != 'T') {
        return;
    }
    const char *html = "HTTP/1.1 200 OK\nContent-Type:text/html; Charset=UTF-8\n\r\n<html><body>hello</body></html>";

    uint ack = ntohl(tcp_hdr->th_seq) + payload_size;
    uint seq = ntohl(tcp_hdr->th_ack);
    int http_resp_size = strlen(html);
    response_packet1(ack, seq, web_server->ipid++, html, http_resp_size, TH_ACK | TH_PUSH | TH_FIN, tcp_hdr, ip_hdr,
                     errbuf);

    response_packet1(ack, seq + http_resp_size + 1, web_server->ipid++, NULL, 0, TH_RST, tcp_hdr, ip_hdr, errbuf);
}

pcap_t *init_pcap(const char *dev, const char *filter_exp, char *errbuf) {
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
        snprintf(errbuf, BUFSIZ, "lookup %s failed", dev);
        return NULL;
    }
    pcap_t *pcap = pcap_open_live(dev, 65535, 1, 0, errbuf);
    if (pcap == NULL) {
        return NULL;
    }
    if (filter_exp != NULL) {
        struct bpf_program fp;
        if (pcap_compile(pcap, &fp, filter_exp, 1, netp) == -1) {
            snprintf(errbuf, BUFSIZ, "Compile filter expression failed %s cause: %s", filter_exp,
                     pcap_geterr(pcap));
            pcap_close(pcap);
            return NULL;
        }
        if (pcap_setfilter(pcap, &fp) == -1) {
            snprintf(errbuf, BUFSIZ, "Install filter failed %s", pcap_geterr(pcap));
            pcap_close(pcap);
            return NULL;
        }
    }
    return pcap;
}

#ifdef SIOCGIFHWADDR
int get_mac_address(char* mac_addr, const char* if_name){
    struct ifreq ifinfo;
    strcpy(ifinfo.ifr_name, if_name);
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    int result = ioctl(sd, SIOCGIFHWADDR, &ifinfo);
    close(sd);

    if ((result == 0) && (ifinfo.ifr_hwaddr.sa_family == 1)) {
        memcpy(mac_addr, ifinfo.ifr_hwaddr.sa_data, IFHWADDRLEN);
        return TRUE;
    }
    else {
        return FALSE;
    }
}
#else

int get_mac_address(char *mac_addr, const char *if_name) {
    struct ifaddrs *iflist;
    int found = FALSE;
    if (getifaddrs(&iflist) == 0) {
        for (struct ifaddrs *cur = iflist; cur; cur = cur->ifa_next) {
            if ((cur->ifa_addr->sa_family == AF_LINK) &&
                (strcmp(cur->ifa_name, if_name) == 0) &&
                cur->ifa_addr) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *) cur->ifa_addr;
                memcpy(mac_addr, LLADDR(sdl), sdl->sdl_alen);
                found = TRUE;
                break;
            }
        }

        freeifaddrs(iflist);
    }
    return found;
}

#endif

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage e_www <eth1> <ip>\n");
        return EXIT_FAILURE;
    }
    char errbuf[BUFSIZ];
    pcap_t *pcap = init_pcap(argv[1], NULL, errbuf);
    if (pcap == NULL) {
        log_error("init pcap failed %s\n", errbuf);
        return EXIT_FAILURE;
    }
    //获取mac地址

    log_info("Start Success\n");
    web_server_t *web_server = (web_server_t *) malloc(sizeof(web_server_t));
    web_server->ipid = (uint16_t) libnet_get_prand(LIBNET_PRu16);
    web_server->hw_addr = malloc(255);
    web_server->ifi = argv[1];
    web_server->ip = inet_addr(argv[2]);
    get_mac_address(web_server->hw_addr, argv[1]);

    pcap_loop(pcap, -1, on_packet, (u_char *) web_server);

    //释放资源(其实执行不到)
    free(web_server->hw_addr);
    free(web_server);
    pcap_close(pcap);
    return 0;
}