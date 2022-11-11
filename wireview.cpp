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
    const char *fname = 'filename.txt'; // input file name

    pcap_t *pcap_open_offline(*fname, *errbuf);

    // loop through the input file

    // close the input file

    return 0;
}


void callback() {

}

