#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

void packet_handler(unsigned char* counter, const struct pcap_pkthdr* header, const unsigned char* packetData) {
    char mac_addr[18];
    snprintf(mac_addr, sizeof(mac_addr), "%02X:%02X:%02X:%02X:%02X:%02X",
        packetData[10], packetData[11], packetData[12],
        packetData[13], packetData[14], packetData[15]);

    const char* target_mac = "XX:XX:XX:XX:XX:XX"; // Target MAC address to match

    if (strcmp(mac_addr, target_mac) == 0) {
        printf("Target Wi-Fi Device Probe Request Detected: %s\n", mac_addr);
    }
}

int start_packet_capture() {
    char* dev = "wlan1";  
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open the device for live capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    struct bpf_program compiled_filter; // fp pointer to filter program used by libpcap
    char filter_name[] = "type mgt subtype probe-req";  // filter to only allow probe request
    if (pcap_compile(handle, &compiled_filter, filter_name, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_name, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_name, pcap_geterr(handle));
        return 2;
    }

    // Capture packets indefinitely
    printf("Scanning for Wi-Fi probe requests...\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the handle
    pcap_close(handle);
    return 0;
}

int main() {
    return start_packet_capture();
}
