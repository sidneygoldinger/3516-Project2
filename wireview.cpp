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


void callback() {

}

int main (int argc, char **argv) {
    // open the input file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handler callback;

    pcap_t *openedFile = pcap_open_offline("filename.txt", errbuf);
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

    // loop through the input file
    pcap_loop(openedFile,-1,callback,NULL);

    // close the input file
    pcap_close(openedFile);

    return 0;
}

