#ifndef ARGPARSE_H
# define ARGPARSE_H

int fill_ipv4_from_string(char *str, uint8_t buf[IPV4_LEN]);
int fill_mac_from_string(char *str, uint8_t buf[ETH_ALEN]);

# include "define.h"

#endif