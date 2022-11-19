//
// Created by Sidney Goldinger on 11/11/22.
//
/////// Imports ///////
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
/////// Global variables ///////
int totalNumberPackets = 0;

// /* 10Mb/s ethernet header */
// struct ether_header
// {
//   u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
//   u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
//   u_int16_t ether_type;		        /* packet type ID field	*/
// }

void callback(u_char *thing1, const struct pcap_pkthdr *thing2, const u_char *thing3) {
    // print start date and time

    // print duration of packet capture

    // count packets (and set a global to this)
    static int count = 1;
    //printf("in callback, rejoice: %d\n", count);
    totalNumberPackets = count;
    count++;
    printf("size of packet in bytes: %d\n", thing2->len);
    struct ether_header* e_header = ((struct ether_header*) thing3);
    //ether_type value meanings  
    //https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
    printf("IP or ARP: %d\n", ntohs(e_header->ether_type));
    
    printf("ethernet header source: %s\n", ether_ntoa((const struct ether_addr *)&e_header->ether_shost));
    printf(" destination: %s \n", ether_ntoa((const struct ether_addr *)&e_header->ether_dhost));


    thing3 = thing3 + sizeof(*e_header);
    printf("%ld\n", sizeof(*e_header));

    //     struct ip {
    // #if BYTE_ORDER == LITTLE_ENDIAN 
    //     u_char  ip_hl:4,        /* header length */
    //         ip_v:4;         /* version */
    // #endif
    // #if BYTE_ORDER == BIG_ENDIAN 
    //     u_char  ip_v:4,         /* version */
    //         ip_hl:4;        /* header length */
    // #endif
    //     u_char  ip_tos;         /* type of service */
    //     short   ip_len;         /* total length */
    //     u_short ip_id;          /* identification */
    //     short   ip_off;         /* fragment offset field */
    // #define IP_DF 0x4000            /* dont fragment flag */
    // #define IP_MF 0x2000            /* more fragments flag */
    //     u_char  ip_ttl;         /* time to live */
    //     u_char  ip_p;           /* protocol */
    //     u_short ip_sum;         /* checksum */
    //     struct  in_addr ip_src,ip_dst;  /* source and dest address */
    // };


    struct ip* ip_header = ((struct ip*) thing3);
    printf("ip header source: %s\n", inet_ntoa((struct in_addr)ip_header->ip_src));
    printf("ip header destination: %s\n", inet_ntoa((struct in_addr)ip_header->ip_dst));
    u_char upperProtocolNum = ip_header->ip_p;
    printf("UDP or not (should be 17 for UDP): %d\n", upperProtocolNum);

    //if UDP is carried
    //struct udphdr
    // {
    // u_int16_t uh_sport;                /* source port */
    // u_int16_t uh_dport;                /* destination port */
    // u_int16_t uh_ulen;                /* udp length */
    // u_int16_t uh_sum;                /* udp checksum */
    // };
    if(upperProtocolNum == 17) {
        thing3 = thing3 + sizeof(*ip_header);
        struct udphdr* udp_header = ((struct udphdr*) thing3);
        printf("udp header source port: %d\n", ntohs(udp_header->uh_sport));
        printf("udp header destination port: %d\n", ntohs(udp_header->uh_dport));
    }


    // for(int i = 0; i < ETH_ALEN; i ++) {
    //     hostDestinationAddr[i] = ntohs(e_header->ether_dhost[i]);
    //     printf("%d ", ntohs(e_header->ether_dhost[i]));
    // }
    // printf("destination ethernet address: %s\n", (char*)hostDestinationAddr);

    // do unique senders things

    // do unique recipients things

    // do unique machines list things
    //      and include associated MAC addresses
    //      and IP addr's if possible(?)

    // do unique source ports things

    // do unique destination ports things

    // get packet size
    // record min so far and max so far, and sum for
    //      ultimate average
}


int main (int argc, char **argv) {
    // open the input file
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *openedFile = pcap_open_offline("project2-dns.pcap", errbuf);
    if (openedFile == NULL) {
        printf("The file wasn't opened: %s\n", errbuf);
        return 1;
    }

    // check data was captured using ethernet?
    int wasItEthernet = pcap_datalink(openedFile);
    if (wasItEthernet != 1) {
        printf("The file wasn't ethernet? Returned: %d\n", wasItEthernet);
        return 1;
    }
    else {
        printf("The file was ethernet! Yay!\n");
    }

    // loop through the input file
    pcap_loop(openedFile,-1,callback,NULL); // change second input to -1

    // close the input file
    pcap_close(openedFile);

    // print total number of packets:
    printf("TOTAL PACKETS IS %d\n", totalNumberPackets);

    return 0;
}

