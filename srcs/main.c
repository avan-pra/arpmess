#include <unistd.h>
#include "utils.h"
#include "struct.h"

int main(int argc, char **argv)
{
	struct arguments arguments = { 0x0 };
	nmap_r **scan = NULL; /* hold result of the arp nmap scan */
	int action;

	argparse(argc, argv, &arguments);

	if (getuid() != 0)
	{ ERROR_UID(getuid(), argv[0]); goto err; }

	/* we are getting network interface info in two rounds to */
	/* confirm the existence of the interface specified by the user or get one
	retreive gateway protocol address */
	if (get_network_interface(arguments.ifacename, arguments.gateway_pa) != 0)
		goto err;//error no iface found
	/* get self ipv4, self mac addr, netmask of the network */
	if (get_network_interface_addresses(arguments.ifacename, arguments.self_pa, arguments.self_pa, arguments.netmask) != 0)
		goto err;//error no hardware addr or protocol address for specified interface

	/* the target arg should be handle around here */
	/* arguments.target_list == NULL */
	if (!(scan = nmapscan(&arguments))) 
		goto err;
	
	action = ask_attack_type();

	if (action == ACTION_ONE) {
		int hostidx = ask_index(scan, &arguments);
	}

	free_arp_scan(scan);
	return 0;

err:
	if (scan)
		free_arp_scan(scan);
	ERROR_EXIT();
	return 1;
}
