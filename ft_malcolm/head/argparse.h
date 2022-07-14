#ifndef ARGPARSE_H
# define ARGPARSE_H

int fill_ipv4_from_string(char *str, uint8_t buf[IPV4_LEN]);
int fill_mac_from_string(char *str, uint8_t buf[ETH_ALEN]);
int fill_arg(char **argv, attack *attacks_infos);

# include "define.h"

#endif