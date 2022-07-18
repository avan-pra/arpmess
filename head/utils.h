#ifndef UTILS_H
# define UTILS_H

# include "struct.h"

/* argparse.c */
int argparse(int argc, char **argv, struct arguments *arguments);

/* network.c */
int get_gateway_ip(void);
int get_network_interface(char ifacename[IF_NAMESIZE], uint8_t gateway_pa[IPV4_LEN]);
int get_network_interface_addresses(char name[IF_NAMESIZE], uint8_t ipv4[IPV4_LEN], uint8_t mac[ETH_ALEN], uint8_t netmask[ETH_ALEN]);
nmap_r **nmapscan(struct arguments *arguments);
nmap_r **parse_arp_scan(FILE *fd, const struct arguments *arguments);
void free_arp_scan(nmap_r **scan);

/* interactive.c */
int ask_user_for_gateway();
int ask_attack_type();
long long ask_index(nmap_r **scan, const struct arguments *arguments);

/* utils.c */
int is_hbroadcast_addr(const uint8_t addr[ETH_ALEN]);
int is_ipv4_equal(const uint8_t pa1[IPV4_LEN], const uint8_t pa2[IPV4_LEN]);
int is_mac_equal(const uint8_t pa1[ETH_ALEN], const uint8_t pa2[ETH_ALEN]);
void print_mac_address(const uint8_t addr[ETH_ALEN]);
void print_ipv4_address(const uint8_t addr[IPV4_LEN]);
void copy_ipv4(uint8_t dest[IPV4_LEN], const uint8_t src[IPV4_LEN]);
void copy_mac(uint8_t dest[ETH_ALEN], const uint8_t src[ETH_ALEN]);
int fill_vendor_from_manuf_file(nmap_r **scan);

#endif
