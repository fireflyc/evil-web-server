#include "packet.h"

int response_arp(web_server_t *web_server, struct libnet_ethernet_hdr *eth_hdr, struct libnet_ipv4_hdr *ip_hdr, char *errbuf) {
    libnet_t *net = libnet_init(LIBNET_LINK, web_server->ifi, errbuf);
    if (net == NULL) {
        return -1;
    }
    libnet_ptag_t t = libnet_build_arp(
            ARPHRD_ETHER,                           /* hardware addr */
            ETHERTYPE_IP,                           /* protocol addr */
            ETHER_ADDR_LEN,                                      /* hardware addr size */
            4,                                      /* protocol addr size */
            ARPOP_REPLY,                            /* operation type */
            (const uint8_t *) web_server->hw_addr,                               /* sender hardware addr */
            (const uint8_t *) &web_server->ip,                           /* sender protocol addr */
            eth_hdr->ether_shost,                               /* target hardware addr */
            (const uint8_t *) &ip_hdr->ip_dst.s_addr,                           /* target protocol addr */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            net,                                      /* libnet handle */
            0);                                     /* libnet id */

    if (t == -1) {
        snprintf(errbuf, BUFSIZ, "Can't build ARP header: %s\n", libnet_geterror(net));
        libnet_destroy(net);
        return EXIT_FAILURE;
    }
    t = libnet_autobuild_ethernet(
            eth_hdr->ether_dhost,                               /* ethernet destination */
            ETHERTYPE_ARP,                          /* protocol type */
            net);                                     /* libnet handle */
    if (t == -1) {
        snprintf(errbuf, BUFSIZ, "Can't build ethernet header: %s\n", libnet_geterror(net));
        libnet_destroy(net);
        return EXIT_FAILURE;
    }
    int write_size = libnet_write(net);
    if (write_size == -1) {
        snprintf(errbuf, BUFSIZ, "Writer error %s", libnet_geterror(net));
        libnet_destroy(net);
        return EXIT_FAILURE;
    }
    libnet_destroy(net);
    return EXIT_SUCCESS;
}

int response_packet1(uint ack, uint seq, uint16_t ipid, const char *response, uint16_t response_size, uint8_t control,
                     struct libnet_tcp_hdr *tcp_hdr, struct libnet_ipv4_hdr *ip_hdr, char *errbuf) {
    //不指定网卡
    libnet_t *net = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (net == NULL) {
        return -1;
    }
    libnet_ptag_t t = libnet_build_tcp(
            ntohs(tcp_hdr->th_dport), // source port
            ntohs(tcp_hdr->th_sport), // dest port
            seq, // sequence number
            ack, // ack number
            control, // flags //ACK确认用户发送的请求数据包 push立即发送 FIN只在最后一条数据设置
            255, // window size
            0, // checksum
            0, // urg ptr //???
            (uint16_t) (LIBNET_TCP_H + response_size), // total length of the TCP packet
            (const uint8_t *) response, // response
            response_size, // response_length
            net, // libnet_t pointer
            0 // ptag
    );
    if (t == -1) {
        snprintf(errbuf, BUFSIZ, "Can't build TCP header: %s", libnet_geterror(net));
        libnet_destroy(net);
        return EXIT_FAILURE;
    }
    t = libnet_build_ipv4(
            (uint16_t) (LIBNET_IPV4_H + LIBNET_TCP_H + response_size), // length
            // TOS bits 最小延时、最大吞吐量、最高可靠性 最小费用 这个字段一般会被设备忽略。
            0, //不设置
            ipid, // IPID 16位随机数
            IP_DF, // fragmentation 不分片
            64, // TTL 一般设置为64达到64就可以死了延时太高了
            IPPROTO_TCP, // protocol, 表示使用TCP协议
            0, // checksum
            ip_hdr->ip_dst.s_addr, // source address
            ip_hdr->ip_src.s_addr, // dest address
            NULL, // response
            0, // response length //
            net, // libnet_t pointer
            0
    );
    if (t == -1) {
        snprintf(errbuf, BUFSIZ, " Can't build IP header: %s", libnet_geterror(net));
        libnet_destroy(net);
        return EXIT_FAILURE;
    }
    int write_size = libnet_write(net);
    if (write_size == -1) {
        snprintf(errbuf, BUFSIZ, "Writer error %s", libnet_geterror(net));
        libnet_destroy(net);
        return EXIT_FAILURE;
    }
    libnet_destroy(net);
    return EXIT_SUCCESS;
}