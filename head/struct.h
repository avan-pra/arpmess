#ifndef STRUCT_H
# define STRUCT_H

# include <stdint.h>
# include <linux/if_ether.h>
# include <net/if.h>
# include <argp.h>

# include "define.h"

/* Ethernet frame header */
typedef struct {
	uint8_t dest_addr[6];	/* example: 02:42:ac:11:00:03 / hardware address */
	uint8_t src_addr[6];	/* same */
	uint16_t eth_type;	/* 0x0806 for ARP */
}	eth;

/* ARP packet */
typedef struct
{
	uint16_t htype; /* Hardware address space */
	uint16_t ptype; /* Protocol address space. */
	uint8_t hlen; /* byte len of each hardware addr */
	uint8_t plen; /* byte len of each protocol addr */
	uint16_t operation;	/* operation type (request) */
	uint8_t sender_ha[ETH_ALEN];	/* sender hardware addr */
	uint8_t sender_pa[IPV4_LEN];	/* sender protocol (IPv4) addr */
	uint8_t target_ha[ETH_ALEN];	/* target hardware addr */
	uint8_t target_pa[IPV4_LEN];	/* target protocol (IPv4) addr */
}	arp;

typedef struct
{
	uint8_t spoofed_pa[IPV4_LEN];	/* sender protocol (IPv4) addr */
	uint8_t spoofed_ha[ETH_ALEN];	/* sender hardware addr */ 
	uint8_t target_pa[IPV4_LEN];	/* target protocol (IPv4) addr */
	uint8_t target_ha[ETH_ALEN];	/* target hardware addr */ 
	uint8_t self_pa[IPV4_LEN];	/* sender protocol (IPv4) addr */
	uint8_t self_ha[ETH_ALEN];	/* sender hardware addr */
	char ifacename[IF_NAMESIZE];
}	attack;

/* struct which hold the programm args */
typedef struct arguments
{
	int verbose;
	char *target_list;
	char ifacename[IF_NAMESIZE];
	uint32_t scanamount;	/* number of result in the scan */
	uint8_t gateway_pa[IPV4_LEN];	/* gateway protocol (IPv4) addr */
	uint8_t gateway_ha[ETH_ALEN];	/* gateway hardware addr */
	uint8_t netmask[IPV4_LEN];	/* network mask */
	uint8_t self_pa[IPV4_LEN];	/* sender protocol (IPv4) addr */
	uint8_t self_ha[ETH_ALEN];	/* sender hardware addr */
}	t_arguments;

typedef struct nmap_t
{
	uint32_t idx;
	uint8_t pa[IPV4_LEN];
	uint8_t ha[ETH_ALEN];
	char *vendor;
	char *vendor_extra;
}	nmap_r;

# endif