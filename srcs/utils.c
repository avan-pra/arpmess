#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "define.h"
#include "struct.h"

int g_stop = 1;

void sighandler(int signum)
{
	// fucking wall wextra werror
	g_stop = signum - signum;
}

int start_signal()
{
	signal(SIGINT, sighandler);
	return 0;
}

int stop_signal()
{
	signal(SIGINT, SIG_DFL);
	return 0;
}

void print_mac_address(const uint8_t addr[ETH_ALEN])
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void print_ipv4_address(const uint8_t addr[IPV4_LEN])
{
	printf("%d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
}

void copy_ipv4(uint8_t dest[IPV4_LEN], const uint8_t src[IPV4_LEN])
{
	for (size_t i = 0; i < IPV4_LEN; ++i)
		dest[i] = src[i];
}

void copy_mac(uint8_t dest[ETH_ALEN], const uint8_t src[ETH_ALEN])
{
	for (size_t i = 0; i < ETH_ALEN; ++i)
		dest[i] = src[i];
}

int is_ipv4_equal(const uint8_t pa1[IPV4_LEN], const uint8_t pa2[IPV4_LEN])
{
	for (size_t i = 0; i < IPV4_LEN; ++i) {
		if (pa1[i] != pa2[i])
			return 0;
	}
	return 1;
}

int is_mac_equal(const uint8_t pa1[ETH_ALEN], const uint8_t pa2[ETH_ALEN])
{
	for (size_t i = 0; i < ETH_ALEN; ++i) {
		if (pa1[i] != pa2[i])
			return 0;
	}
	return 1;
}

int is_mac_empty(const uint8_t mac[ETH_ALEN])
{
	for (size_t i = 0; i < ETH_ALEN; ++i) {
		if (mac[i] != 0)
			return 0;
	}
	return 1;
}

int is_mac_equal_manuf(const uint8_t pa1[ETH_ALEN], const uint8_t pa2[ETH_ALEN])
{
	for (size_t i = 0; i < 3; ++i) {
		if (pa1[i] != pa2[i])
			return 0;
	}
	return 1;
}

/* return wheter the given addr is a hardware broadcast address */
int is_hbroadcast_addr(const uint8_t addr[ETH_ALEN])
{
	for (size_t i = 0; i < ETH_ALEN; ++i) {
		if (addr[i] != 255)
			return 0;	
	}
	return 1;
}

nmap_r *get_self_from_scan(nmap_r **scan)
{
	for (size_t i = 0; scan[i] != NULL; ++i) {
		if (scan[i]->self == 1)
			return scan[i];
	}
	return NULL;
}

nmap_r *get_gateway_from_scan(nmap_r **scan)
{
	for (size_t i = 0; scan[i] != NULL; ++i) {
		if (scan[i]->gateway == 1)
			return scan[i];
	}
	return NULL;
}

static void free_manu_db(manuf_db **db)
{
	for (size_t i = 0; db && db[i] != NULL; ++i) {
		if (db[i]->vendor != NULL)
			free(db[i]->vendor);
		if (db[i]->vendor_extra != NULL)
			free(db[i]->vendor_extra);
		free(db[i]);
	}
	if (db)
		free(db);
}

# define REALLOCSIZE 1000
static manuf_db **create_manu_database(FILE *fd)
{
	char *line = NULL, *saveptr = NULL;
	int sres = 0;
	size_t size = 0;
	size_t dblen = 0;
	manuf_db **db = NULL;
	size_t i = 0;

	/* read the file line by line */
	while (getline(&line, &size, fd) > 0) {
		/* realloc if size is not greate enough */
		if (i + 1 >= dblen) {
			if (!(db = realloc(db, (dblen + REALLOCSIZE) * sizeof(manuf_db*))))
				{ ERROR_MALLOC(); goto err; }
			for (size_t j = i; j < dblen + REALLOCSIZE; ++j) {
				memset(&db[j], 0, sizeof(manuf_db*));
			}
			dblen = dblen + REALLOCSIZE;
		}
		/* is it a comment if so dont increment anything*/
		if (line[0] == '#' || line[0] == '\n') {
			free(line);
			line = NULL;
			continue;
		}
		if (!(db[i] = calloc(1, sizeof(manuf_db))))
			{ ERROR_MALLOC(); goto err; }
		sres = sscanf(line, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &db[i]->ha[0], &db[i]->ha[1], &db[i]->ha[2], &db[i]->ha[3], &db[i]->ha[4], &db[i]->ha[5]);
		/* ignore 6 len entry */
		if (sres != 3) {
			free(db[i]);
			continue;
		}
		strtok_r(line, "\t", &saveptr);

		/* handle vendor */
		if (!(db[i]->vendor = strdup(strtok_r(NULL, "\t", &saveptr))))
			{ ERROR_MALLOC(); goto err; }
		if (db[i]->vendor != NULL && db[i]->vendor[strlen(db[i]->vendor) - 1] == '\n')
			db[i]->vendor[strlen(db[i]->vendor) - 1] = 0x0;

		/* handle vendor_extra */
		db[i]->vendor_extra = strtok_r(NULL, "\t", &saveptr);
		if (db[i]->vendor_extra != NULL) {
			if (!(db[i]->vendor_extra = strdup(db[i]->vendor_extra)))
				{ ERROR_MALLOC(); goto err; }
		}
		if (db[i]->vendor_extra != NULL && db[i]->vendor_extra[strlen(db[i]->vendor_extra) - 1] == '\n')
			db[i]->vendor_extra[strlen(db[i]->vendor_extra) - 1] = 0x0;

		++i;
		free(line);
		line = NULL;
	}
	free(line);

	return db;

err:
	free_manu_db(db);
	return NULL;
}

int fill_vendor_from_manuf_file(nmap_r **scan) {
	FILE *fd = NULL;
	manuf_db **db = NULL;

	if (!(fd = fopen("manuf", "r")))
		{ ERROR_NO_MANUF_FILE(); return 0; }
	if (!(db = create_manu_database(fd)))
		goto err;
	for (size_t i = 0; scan[i]; ++i) {
		for (size_t j = 0; db[j] != NULL; ++j) {
			if (is_mac_equal_manuf(db[j]->ha, scan[i]->ha))
			{
				if (db[j]->vendor != NULL) {
					if (!(scan[i]->vendor = strdup(db[j]->vendor)))
						goto err;
				}
				if (db[j]->vendor_extra != NULL) {
					if (!(scan[i]->vendor_extra = strdup(db[j]->vendor_extra)))
						goto err;
				}
				break;
			}
		}
	}
	fclose(fd);
	free_manu_db(db);
	return 0;

err:
	if (fd)
		fclose(fd);
	if (db)
		free_manu_db(db);
	return 1;
}
