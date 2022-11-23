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

//#include <netinet/ether.h> // for linux
#include <netinet/if_ether.h> // for mac

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <string>
#include <unordered_set>
//#include <netinet/arp.h>
#include <iostream>
using namespace std;


/////// Global variables ///////
int totalNumberPackets = 0;
int smallestPacketSize = 99999999;
int biggestPacketSize = 0;
int sumOfPacketSizes = 0;

int startingSeconds = 0;
int startingUsecs = 0;

int endingSeconds = 0;
int endingUsecs = 0;

std::unordered_set <char*> sendingPorts;
std::unordered_set <char*> receivingPorts;
std::unordered_set <std::string> arpAddresses; //MAC or IP

const struct pcap_pkthdr *startingTimeval;

/**
 * Prints out the starting date and time of the packet
 * @param thing2 timeval of the packet starting time
 */
void dateAndTime(const struct pcap_pkthdr *thing2) {
    long int seconds = thing2->ts.tv_sec;
    //printf("seconds: %ld\n", seconds);

    // Save the time in Human
    // readable format
    string ans = "";

    // Number of days in month
    // in normal year
    int daysOfMonth[] = { 31, 28, 31, 30, 31, 30,
                          31, 31, 30, 31, 30, 31 };

    long int currYear, daysTillNow, extraTime, extraDays,
            index, date, month, hours, minutes, secondss,
            flag = 0;

    // Calculate total days unix time T
    daysTillNow = seconds / (24 * 60 * 60);
    extraTime = seconds % (24 * 60 * 60);
    currYear = 1970;

    // Calculating current year
    while (true) {
        if (currYear % 400 == 0
            || (currYear % 4 == 0 && currYear % 100 != 0)) {
            if (daysTillNow < 366) {
                break;
            }
            daysTillNow -= 366;
        }
        else {
            if (daysTillNow < 365) {
                break;
            }
            daysTillNow -= 365;
        }
        currYear += 1;
    }
    // Updating extradays because it
    // will give days till previous day
    // and we have include current day
    extraDays = daysTillNow + 1;

    if (currYear % 400 == 0
        || (currYear % 4 == 0 && currYear % 100 != 0))
        flag = 1;

    // Calculating MONTH and DATE
    month = 0, index = 0;
    if (flag == 1) {
        while (true) {

            if (index == 1) {
                if (extraDays - 29 < 0)
                    break;
                month += 1;
                extraDays -= 29;
            }
            else {
                if (extraDays - daysOfMonth[index] < 0) {
                    break;
                }
                month += 1;
                extraDays -= daysOfMonth[index];
            }
            index += 1;
        }
    }
    else {
        while (true) {

            if (extraDays - daysOfMonth[index] < 0) {
                break;
            }
            month += 1;
            extraDays -= daysOfMonth[index];
            index += 1;
        }
    }

    // Current Month
    if (extraDays > 0) {
        month += 1;
        date = extraDays;
    }
    else {
        if (month == 2 && flag == 1)
            date = 29;
        else {
            date = daysOfMonth[month - 1];
        }
    }

    // Calculating HH:MM:YYYY
    hours = extraTime / 3600;
    minutes = (extraTime % 3600) / 60;
    secondss = (extraTime % 3600) % 60;

    ans += std::to_string(date);
    ans += "/";
    ans += std::to_string(month);
    ans += "/";
    ans += std::to_string(currYear);
    ans += " ";
    ans += std::to_string(hours);
    ans += ":";
    ans += std::to_string(minutes);
    ans += ":";
    ans += std::to_string(secondss);

    // Return the time
    printf("Start date and time: ");
    cout << ans << "\n";
}

/**
 * Does stats things so that ave, min, and max can be printed at end.
 * @param packetSize the size of the packet to be included in the stats
 */
void packetSizeThings(int packetSize) {
    // smallest size
    if (packetSize < smallestPacketSize) {
        smallestPacketSize = packetSize;
    }

    // biggestsize
    if (packetSize > biggestPacketSize) {
        biggestPacketSize = packetSize;
    }

    // increase the sum
    sumOfPacketSizes += packetSize;
}


void callback(u_char *thing1, const struct pcap_pkthdr *thing2, const u_char *thing3) {
    // count packets (and set a global to this)
    static int count = 1;
    totalNumberPackets = count;

    // save start date and time if count = 1
    if (count == 1) { dateAndTime(thing2); }

    // get starting seconds + usecs if count = 1
    if (count == 1) {
        startingSeconds = thing2->ts.tv_sec;
        startingUsecs = thing2->ts.tv_usec;
    }

    // get ending seconds + usecs (updates every most recent packet)
    endingSeconds = thing2->ts.tv_sec;
    endingUsecs = thing2->ts.tv_usec;

    // increment packet count
    count++;

    // go do packet size stats things
    //printf("size of packet in bytes: %d\n", thing2->len); // TODO: is this everything past the tcpdump??
    packetSizeThings(thing2->len);


    struct ether_header* e_header = ((struct ether_header*) thing3);
    u_int16_t e_type = ntohs(e_header->ether_type);
    //printf("IP or ARP: %d\n", e_type);

    //add these to two separate maps ex. ethernetSenders and ethernetRecipients
    //the maps will map hex-colon addresses to counts(# of times that the address has sent/received)
    //if the ethernet address was already in the map, add to its count
    //printf("ethernet header source: %s\n", ether_ntoa((const struct ether_addr *)&e_header->ether_shost));
    //printf("ethernet header destination: %s \n", ether_ntoa((const struct ether_addr *)&e_header->ether_dhost));


    thing3 = thing3 + sizeof(*e_header);
    //printf("%ld\n", sizeof(*e_header));

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
    // if IP
    if(e_type == 2048) {
        //printf("packet is IP\n");
        //add these to two separate maps ex. ipSenders and ipRecipients
        //the maps will map ip addresses to counts(# of times that the address has sent/received)
        //if the ip address was already in the map, add to its count
        //printf("IP header source: %s\n", inet_ntoa((struct in_addr)ip_header->ip_src));
        //printf("IP header destination: %s\n", inet_ntoa((struct in_addr)ip_header->ip_dst));
        u_char upperProtocolNum = ip_header->ip_p;
        //printf("UDP or not (should be 17 for UDP): %d\n", upperProtocolNum);

        //only check for UDP if there is an IP header?????????

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
            //add these to two separate maps ex. sendingPorts and receivingPorts
            //the maps will map port numbers to counts(# of times that the port has sent/received)
            //if the port was already in the map, add to its count
            //printf("UDP header source port: %d\n", ntohs(udp_header->uh_sport));
            //printf("UDP header destination port: %d\n", ntohs(udp_header->uh_dport));
        } else {
            //printf("No UDP being carried!\n");
        }
    // if ARP
    } else if(e_type == 2054) {
        //arp packets never have UDP or TCP?????????
        //Might make sense because TCP and UDP are for inter-network stuffs and ARP only operates on data link layer
        //printf("packet is ARP\n");
        //arphdr fields
        // uint16_t ar_hrd;	Format of hardware address
        // uint16_t ar_pro;	Format of protocol address
        // uint8_t ar_hln;	Length of hardware address
        // uint8_t ar_pln;	Length of protocol address
        // uint16_t ar_op;	ARP opcode (command)

        //ether_arp fields
        // struct arphdr ea_hdr;	fixed-size header
        // uint8_t arp_sha[6];	sender hardware address
        // uint32_t arp_spa;	sender protocol address
        // uint8_t arp_tha[6];	target hardware address
        // uint32_t arp_tpa;	target protocol address

        //ether_arp might look like this instead?????
        // struct  ether_arp {
        // struct  arphdr ea_hdr;          /* fixed-size header */
        // u_int8_t arp_sha[ETH_ALEN];     /* sender hardware address */
        // u_int8_t arp_spa[4];            /* sender protocol address */
        // u_int8_t arp_tha[ETH_ALEN];     /* target hardware address */
        // u_int8_t arp_tpa[4];            /* target protocol address */
        // };

        struct arphdr* arp_header = ((struct arphdr*) thing3);
        uint16_t protocolType = ntohs(arp_header->ar_pro);
        //printf("Protocol type: %d\n", protocolType);
        if(protocolType == 2048) {
            //print out IP address stuff
            struct ether_arp* arp_body = ((struct ether_arp*) thing3);

            //add these to same hashset (only keep track of unique senders and targets/"machines participating in ARP")
            //printf("Sender IP address: %d.%d.%d.%d\n", arp_body->arp_spa[0], arp_body->arp_spa[1], arp_body->arp_spa[2], arp_body->arp_spa[3]);
            //printf("Target IP address: %d.%d.%d.%d\n", arp_body->arp_tpa[0], arp_body->arp_tpa[1], arp_body->arp_tpa[2], arp_body->arp_tpa[3]);
            std::string senderIP = std::to_string(arp_body->arp_spa[0]) + "." + std::to_string(arp_body->arp_spa[1]) + "." +
                                   std::to_string(arp_body->arp_spa[2]) + "." + std::to_string(arp_body->arp_spa[3]);
            std::string targetIP = std::to_string(arp_body->arp_tpa[0]) + "." + std::to_string(arp_body->arp_tpa[1]) + "." +
                                   std::to_string(arp_body->arp_tpa[2]) + "." + std::to_string(arp_body->arp_tpa[3]);

            arpAddresses.insert(senderIP);
            arpAddresses.insert(targetIP);
        }


        struct ether_arp* arp_body = ((struct ether_arp*) thing3);
        //add these to the same hashset (only keep track of unique senders and targets/"machines participating in ARP")
        //printf("Sender MAC address: %s\n", ether_ntoa((const struct ether_addr *)&arp_body->arp_sha));
        //printf("Target MAC address: %s\n", ether_ntoa((const struct ether_addr *)&arp_body->arp_tha));
        std::string senderMAC(ether_ntoa((const struct ether_addr *)&arp_body->arp_sha));
        std::string targetMAC(ether_ntoa((const struct ether_addr *)&arp_body->arp_tha));
        arpAddresses.insert(senderMAC);
        arpAddresses.insert(targetMAC);
        //ip or mac participating in ARP -> number of times it has been seen
        //ip1 -> 2
        //ip2 -> 2
        //mac1 -> 2
        //mac2 -> 2
        //mac3 -> 3

        //OR

        //just a list of unique senders (no mapping, more like a hashset) I'm thinking this one (currently implemented)
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
    //printf("\n");
    //printf("\n");
}


int main (int argc, char **argv) {
    // open the input file
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *openedFile = pcap_open_offline("project2-arp-storm.pcap", errbuf);
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
        //printf("The file was ethernet! Yay!\n");
    }

    // loop through the input file
    memset(&totalNumberPackets, 0, sizeof(totalNumberPackets));
    pcap_loop(openedFile,-1,callback,NULL); // change second input to -1

    //printf("arpAddresses: \n");
    for(std::string s : arpAddresses) {
        //printf("%s\n", s.c_str());
    }
    // close the input file
    pcap_close(openedFile);

    // FINAL PRINTING

    // print total time it took:

    int totalSeconds = startingSeconds - endingSeconds;
    int totalUsecs = startingUsecs - endingUsecs;

    printf("The packet capture took %d seconds and %d microseconds.\n", totalSeconds, totalUsecs);

    // print total number of packets:
    printf("There are %d total packets\n", totalNumberPackets);

    // print unique senders and recipients things

    // print ARP things

    // print UDP things

    // ave, min, max packet sizes
    printf("Smallest packet size: %d\n", smallestPacketSize);
    printf("Biggest packet size: %d\n", biggestPacketSize);
    double averagePacketSize = (double) sumOfPacketSizes/(double) totalNumberPackets;
    printf("Average packet size: %f\n", averagePacketSize);
    return 0;
}