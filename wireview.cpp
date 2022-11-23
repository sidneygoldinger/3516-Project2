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

#include <netinet/ether.h> // for linux
//#include <netinet/if_ether.h> // for mac

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <math.h>
//#include <netinet/arp.h>
#include <iostream>
using namespace std;


/////// Global variables ///////
int totalNumberPackets = 0;
int smallestPacketSize = (int)INFINITY;
int biggestPacketSize = 0;
int sumOfPacketSizes = 0;

int startingSec = 0;
int startingUsec = 0;
int endingSec = 0;
int endingUsec = 0;

std::unordered_map<int, int> sendingPorts;
std::unordered_map<int, int> receivingPorts;
std::unordered_map<std::string, int> sendingIPs;
std::unordered_map<std::string, int> receivingIPs;
std::unordered_map<std::string, int> sendingMACs;
std::unordered_map<std::string, int> receivingMACs;
std::unordered_map<std::string, std::string> arpAddresses; //MAC or IP

// /* 10Mb/s ethernet header */
// struct ether_header
// {
//   u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
//   u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
//   u_int16_t ether_type;		        /* packet type ID field	*/
// }

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
    printf("Date and time: ");
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

    // do date and time starting
    if (count == 1) {
        dateAndTime(thing2);
        startingSec = thing2->ts.tv_sec;
        startingUsec = thing2->ts.tv_usec;
    }
    // record all possible ending times
    endingSec = thing2->ts.tv_sec;
    endingUsec = thing2->ts.tv_usec;


    count++;

    // go do packet size stats things
    //printf("size of packet in bytes: %d\n", thing2->len);
    packetSizeThings(thing2->len);


    // other things?
    struct ether_header* e_header = ((struct ether_header*) thing3);
    //ether_type value meanings
    //https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
    //2048 -> IPv4
    //2054 -> ARP
    u_int16_t e_type = ntohs(e_header->ether_type);
    //printf("IP or ARP: %d\n", e_type);

    //add these to two separate maps ex. ethernetSenders and ethernetRecipients
    //the maps will map hex-colon addresses to counts(# of times that the address has sent/received)
    //if the ethernet address was already in the map, add to its count
    //printf("ethernet header source: %s\n", ether_ntoa((const struct ether_addr *)&e_header->ether_shost));
    //printf("ethernet header destination: %s \n", ether_ntoa((const struct ether_addr *)&e_header->ether_dhost));

    if(!sendingMACs.count(ether_ntoa((const struct ether_addr *)&e_header->ether_shost)) > 0) {
        sendingMACs.insert(std::pair<std::string, int>(std::string(ether_ntoa((const struct ether_addr *)&e_header->ether_shost)), 1));
    } else {
        sendingMACs.find(std::string(ether_ntoa((const struct ether_addr *)&e_header->ether_shost)))->second ++;
    }

    if(!receivingMACs.count(ether_ntoa((const struct ether_addr *)&e_header->ether_dhost)) > 0) {
        receivingMACs.insert(std::pair<std::string, int>(std::string(ether_ntoa((const struct ether_addr *)&e_header->ether_dhost)), 1));
    } else {
        receivingMACs.find(std::string(ether_ntoa((const struct ether_addr *)&e_header->ether_dhost)))->second ++;
    }

    thing3 = thing3 + sizeof(*e_header);

    struct ip* ip_header = ((struct ip*) thing3);
    if(e_type == 2048) {
        //printf("packet is IP\n");
        //add these to two separate maps ex. ipSenders and ipRecipients
        //the maps will map ip addresses to counts(# of times that the address has sent/received)
        //if the ip address was already in the map, add to its count
        //printf("IP header source: %s\n", inet_ntoa((struct in_addr)ip_header->ip_src));
        //printf("IP header destination: %s\n", inet_ntoa((struct in_addr)ip_header->ip_dst));
        if(!sendingIPs.count(inet_ntoa((struct in_addr)ip_header->ip_src)) > 0) {
        sendingIPs.insert(std::pair<std::string, int>(inet_ntoa((struct in_addr)ip_header->ip_src), 1));
        } else {
            sendingIPs.find(inet_ntoa((struct in_addr)ip_header->ip_src))->second ++;
        }

        if(!receivingIPs.count(inet_ntoa((struct in_addr)ip_header->ip_dst)) > 0) {
            receivingIPs.insert(std::pair<std::string, int>(inet_ntoa((struct in_addr)ip_header->ip_dst), 1));
        } else {
            receivingIPs.find(inet_ntoa((struct in_addr)ip_header->ip_dst))->second ++;
        }
        u_char upperProtocolNum = ip_header->ip_p;



        if(upperProtocolNum == 17) {
            thing3 = thing3 + sizeof(*ip_header);
            struct udphdr* udp_header = ((struct udphdr*) thing3);
            //add these to two separate maps ex. sendingPorts and receivingPorts
            //the maps will map port numbers to counts(# of times that the port has sent/received)
            //if the port was already in the map, add to its count
            //printf("UDP header source port: %d\n", ntohs(udp_header->uh_sport));
            //printf("UDP header destination port: %d\n", ntohs(udp_header->uh_dport));
            if(!sendingPorts.count(ntohs(udp_header->uh_sport)) > 0) {
                sendingPorts.insert(std::pair<int, int>(ntohs(udp_header->uh_sport), 1));
            } else {
                sendingPorts.find(ntohs(udp_header->uh_sport))->second++;
            }

            if(!receivingPorts.count(ntohs(udp_header->uh_dport)) > 0) {
                receivingPorts.insert(std::pair<int, int>(ntohs(udp_header->uh_dport), 1));
            } else {
                receivingPorts.find(ntohs(udp_header->uh_dport))->second++;
            }
        } else {
            printf("No UDP being carried!\n");
        }
    } else if(e_type == 2054) {
        struct arphdr* arp_header = ((struct arphdr*) thing3);
        uint16_t protocolType = ntohs(arp_header->ar_pro);
        printf("Protocol type: %d\n", protocolType);


        struct ether_arp* arp_body = ((struct ether_arp*) thing3);
        //add these to the same hashset (only keep track of unique senders and targets/"machines participating in ARP")
        //printf("Sender MAC address: %s\n", ether_ntoa((const struct ether_addr *)&arp_body->arp_sha));
        //printf("Target MAC address: %s\n", ether_ntoa((const struct ether_addr *)&arp_body->arp_tha));
        std::string senderMAC(ether_ntoa((const struct ether_addr *)&arp_body->arp_sha));
        std::string targetMAC(ether_ntoa((const struct ether_addr *)&arp_body->arp_tha));
        //std::string blank(" ");
        arpAddresses.insert(std::pair<std::string, std::string>(senderMAC, ""));
        arpAddresses.insert(std::pair<std::string, std::string>(targetMAC, ""));

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

            arpAddresses.find(senderMAC)->second = senderIP;
            arpAddresses.find(targetMAC)->second = targetIP;
        }
        //ip or mac participating in ARP -> number of times it has been seen
        //ip1 -> 2
        //ip2 -> 2
        //mac1 -> 2
        //mac2 -> 2
        //mac3 -> 3

        //OR

        //just a list of unique senders (no mapping, more like a hashset) I'm thinking this one (currently implemented)
    }


}

//https://www.techiedelight.com/print-keys-values-map-cpp/
template<typename K, typename V>
void print_map(std::unordered_map<K, V> const &m)
{
    for (auto const &pair: m) {
        std::cout << "{" << pair.first << " with count " << pair.second << "}\n";
    }
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
        //printf("The file wasn't ethernet? Returned: %d\n", wasItEthernet);
        return 1;
    }
    else {
        //printf("The file was ethernet! Yay!\n");
    }

    // loop through the input file
    memset(&totalNumberPackets, 0, sizeof(totalNumberPackets));
    pcap_loop(openedFile,-1,callback,NULL); // change second input to -1


    printf("\nEthernet headers:\n");
    printf("\nMACs: \n");
    printf("    Sending MACs: \n");
    print_map(sendingMACs);

    printf("    Receving MACs: \n");
    print_map(receivingMACs);

    printf("\nIP headers:\n");
    printf("    Sending IPs: \n");
    print_map(sendingIPs);

    printf("    Receiving IPs: \n");
    print_map(receivingIPs);

    printf("    Sending Ports: \n");
    print_map(sendingPorts);

    printf("    Receiving Ports: \n");
    print_map(receivingPorts);



    printf("\nARP headers:\n");
    print_map(arpAddresses);

    // close the input file
    pcap_close(openedFile);

    // FINAL PRINTING

    // print total time
    int totalSec = endingSec - startingSec;
    int totalUsec = endingUsec - startingUsec;

    if (totalUsec < 0) {
        totalSec = totalSec - 1;
        totalUsec = totalUsec + 1000000;
    }

    printf("\nThis took %d seconds and %d microseconds\n", totalSec, totalUsec);

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