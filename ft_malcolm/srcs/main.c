#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netdb.h>

#include "define.h"
#include "struct.h"
#include "argparse.h"
#include "utils.h"
#include "arpspoof.h"

int main(int argc, char **argv)
{
	SOCKET iface = 0;
	attack attacks_infos;

	// if (getuid() != 0)
	// 	{ BADUID(getuid()); return 1; }

	if (argc != 5)
		{ USAGE(); return 1; }

	/* set up attack structure (from argv)*/
	if (fill_arg(argv, &attacks_infos) != 0)
		goto err;

	/* get a network interface */
	if (get_network_interface_name(attacks_infos.ifacename) != 0)
		goto err;
	if (get_network_interface_addresses(attacks_infos.ifacename, attacks_infos.self_pa, attacks_infos.self_ha) != 0)
		goto err;

	/* get a raw socket which is bind to device ifacename */
	if ((iface = initiate_socket_for_arp(attacks_infos.ifacename)) == -1)
		goto err;

	/* start attack */
	if (arpspoof(iface, &attacks_infos) != 0)
		goto err;

	close(iface);
	return 0;

err:
	if (iface > 0)
		close(iface);
	if (errno != 0) {
		printf("Error: %s\n", strerror(errno));
		return 1;
	}
	return 1;
}
