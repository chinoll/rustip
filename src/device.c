#include <stdio.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
struct netdev {
    uint32_t addr;
    uint8_t hwaddr[6];
};
void netdev_init(struct netdev *dev,char *addr,int netfd) {
    if (inet_pton(AF_INET, addr, &dev->addr) != 1) {
        perror("ERR: Parsing inet address failed\n");
        exit(1);
    }
    struct ifreq ifr;
    unsigned char mac[6] = {0xdc,0x5c,0x27,0x3c,0xb6,0xdd};
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    strcpy((void *)&ifr.ifr_name, "rustip");
    memcpy(&ifr.ifr_hwaddr.sa_data, mac, 6);
    memcpy(&dev->hwaddr,mac,6);
    ioctl(netfd, SIOCSIFHWADDR, &ifr);
}