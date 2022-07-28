#ifndef UTILS_H
# define UTILS_H

# include "struct.h"

/* argparse.c */
int argparse(int argc, char **argv, struct arguments *arguments);

/* network.c */
int get_gateway_ip(void);
int get_network_interface(char ifacename[IF_NAMESIZE], uint8_t gateway_pa[IPV4_LEN]);
int get_network_interface_addresses(struct arguments *arguments);
nmap_r **nmapscan(struct arguments *arguments);
nmap_r **parse_arp_scan(FILE *fd);
void free_arp_scan(nmap_r **scan);

/* interactive.c */
int ask_user_for_gateway();
int ask_action();
long long ask_index(nmap_r **scan, const struct arguments *arguments);

/* utils.c */
int is_hbroadcast_addr(const uint8_t addr[ETH_ALEN]);
int is_ipv4_equal(const uint8_t pa1[IPV4_LEN], const uint8_t pa2[IPV4_LEN]);
int is_mac_equal(const uint8_t pa1[ETH_ALEN], const uint8_t pa2[ETH_ALEN]);
int is_mac_empty(const uint8_t mac[ETH_ALEN]);
void print_mac_address(const uint8_t addr[ETH_ALEN]);
void print_ipv4_address(const uint8_t addr[IPV4_LEN]);
void copy_ipv4(uint8_t dest[IPV4_LEN], const uint8_t src[IPV4_LEN]);
void copy_mac(uint8_t dest[ETH_ALEN], const uint8_t src[ETH_ALEN]);
int fill_vendor_from_manuf_file(nmap_r **scan);
void PRINT_SCAN_LIST(nmap_r **scan);
int start_signal();
int stop_signal();
nmap_r *get_self_from_scan(nmap_r **scan);
nmap_r *get_gateway_from_scan(nmap_r **scan);

/* attack.c */
int start_attack_one(const struct arguments *arguments, nmap_r *scan);
int start_attack_all(const struct arguments *arguments, nmap_r **scan);
int arpspoof(const struct arguments *arguments, nmap_r **target, long long victimidx);

#endif
