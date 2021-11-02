#include <stdio.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
struct netdev {
    uint32_t addr;
    uint8_t hwaddr[6];
};
void netdev_init(struct netdev *dev,char *addr,char *hwaddr) {
    if (inet_pton(AF_INET, addr, &dev->addr) != 1) {
        perror("ERR: Parsing inet address failed\n");
        exit(1);
    }
    sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev->hwaddr[0],
                                                    &dev->hwaddr[1],
                                                    &dev->hwaddr[2],
                                                    &dev->hwaddr[3],
                                                    &dev->hwaddr[4],
                                                    &dev->hwaddr[5]);
}