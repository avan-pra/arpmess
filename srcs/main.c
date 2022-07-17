#include <unistd.h>
#include "utils.h"
#include "struct.h"

int main(int argc, char **argv)
{
	struct arguments arguments = { 0x0 };

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

	if (arguments.target_list == NULL)
		nmapscan(arguments.gateway_pa, arguments.netmask);
	
	return 0;

err:
	ERROR_EXIT();
	return 1;
}
