//
// Created by Sidney Goldinger on 11/11/22.
//
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main (int argc, char **argv) {
    // open the input file
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *openedFile = pcap_open_offline("filename.txt", errbuf);
    if (openedFile == NULL) {
        cout << "the file wasn't opened: " << errbuf << "\n";
    }

    // loop through the input file

    // close the input file

    return 0;
}


void callback() {

}

