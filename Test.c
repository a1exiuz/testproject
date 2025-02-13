#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_TRACKED_MACS 100  // Maximum MAC addresses to track

char seen_macs[MAX_TRACKED_MACS][18]; // Store last 100 MAC addresses
int mac_count = 0;

void add_mac_to_list(const char* mac_addr) {
    if (mac_count < MAX_TRACKED_MACS) {
        strcpy(seen_macs[mac_count++], mac_addr);
    } else {
        // If list is full, shift and replace the oldest entry
        for (int i = 1; i < MAX_TRACKED_MACS; i++) {
            strcpy(seen_macs[i - 1], seen_macs[i]);
        }
        strcpy(seen_macs[MAX_TRACKED_MACS - 1], mac_addr);
    }
}

int mac_already_seen(const char* mac_addr) {
    for (int i = 0; i < mac_count; i++) {
        if (strcmp(seen_macs[i], mac_addr) == 0) {
            return 1;  // Found duplicate
        }
    }
    return 0;  // New MAC address
}

void packet_handler(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packetData) {
    char mac_addr[18];
    snprintf(mac_addr, sizeof(mac_addr), "%02X:%02X:%02X:%02X:%02X:%02X",
        packetData[10], packetData[11], packetData[12],
        packetData[13], packetData[14], packetData[15]);

    if (!mac_already_seen(mac_addr)) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);

        printf("[%s] Probe Request from: %s\n", timestamp, mac_addr);
        add_mac_to_list(mac_addr);
    }
}

int start_packet_capture() {
    char* dev = "wlan1";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    struct bpf_program compiled_filter;
    char filter_exp[] = "type mgt subtype probe-req";
    if (pcap_compile(handle, &compiled_filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Scanning for Wi-Fi probe requests...\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}

int main() {
    return start_packet_capture();
}
