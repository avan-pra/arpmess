# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <ctype.h>
# include <string.h>
# include "utils.h"

void PRINT_SCAN_LIST(nmap_r **scan)
{
	printf("\n");
	for (size_t i = 0; scan[i]; ++i) {
		if (scan[i]->gateway == 1) {
			printf(ANSI_COLOR_256_ORANGE"gateway"ANSI_COLOR_RESET);
		}
		if (scan[i]->self == 1) {
			printf(ANSI_COLOR_256_ORANGE"you"ANSI_COLOR_RESET);
		}
		if (scan[i]->known_ha == 1) {
			printf("\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"%ld"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\t"MACCOLOR"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"ANSI_COLOR_RESET"\t"VENDORCOLOR"%s"ANSI_COLOR_RESET"\t"VENDORCOLOREXTRA"%s"ANSI_COLOR_RESET"\n",
			i,
			scan[i]->pa[0], scan[i]->pa[1], scan[i]->pa[2], scan[i]->pa[3],
			scan[i]->ha[0], scan[i]->ha[1], scan[i]->ha[2], scan[i]->ha[3], scan[i]->ha[4], scan[i]->ha[5],
			(scan[i]->vendor == NULL ? "N/A" : scan[i]->vendor),
			(scan[i]->vendor_extra == NULL ? "" : scan[i]->vendor_extra));
		}
		else { // probably useless
			printf("\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"%ld"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\t"MACCOLOR"??:??:??:??:??:??"ANSI_COLOR_RESET"\t"VENDORCOLOR"%s"ANSI_COLOR_RESET"\t"VENDORCOLOREXTRA"%s"ANSI_COLOR_RESET"\n",
			i,
			scan[i]->pa[0], scan[i]->pa[1], scan[i]->pa[2], scan[i]->pa[3],
			"N/A",
			"");
		}
	}
}

nmap_r **loadscan(char *filename, nmap_r **scan) {
	FILE *filedumpfile = fopen(filename, "r");
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

	if (!filedumpfile) {
		ERROR_FILE_NOT_FOUND(filename);
		goto err;
	}

    while ((read = getline(&line, &len, filedumpfile)) != -1) {
		nmap_r c_scan = {0x0};
		sscanf(line, "%hhu.%hhu.%hhu.%hhu|%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx|%hhu|%hhu\n",
		&c_scan.pa[0], &c_scan.pa[1], &c_scan.pa[2], &c_scan.pa[3],
		&c_scan.ha[0], &c_scan.ha[1], &c_scan.ha[2], &c_scan.ha[3], &c_scan.ha[4], &c_scan.ha[5],
		&c_scan.gateway, &c_scan.self);
		c_scan.known_ha = 1;
		if (!(scan = add_scan_to_scan_list(scan, &c_scan)))
			goto err;
	}
	sort_scan(scan);
	remove_scan_duplicate(scan);

	TELL_LOAD_FILE_NAME(filename);
	fclose(filedumpfile);

	return scan;

	err:
		if (filedumpfile)
			fclose(filedumpfile);
	return NULL;
}

void dumpscan(nmap_r **scan) {
	char dumpfilename[] = "/tmp/arpmessXXXXXX";
	int fddumpfile = mkstemp(dumpfilename);
	FILE *filedumpfile = fdopen(fddumpfile, "w");

	for (size_t i = 0; scan[i]; ++i) {
		fprintf(filedumpfile, "%hhu.%hhu.%hhu.%hhu|%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx|%hhu|%hhu\n",
		scan[i]->pa[0], scan[i]->pa[1], scan[i]->pa[2], scan[i]->pa[3],
		scan[i]->ha[0], scan[i]->ha[1], scan[i]->ha[2], scan[i]->ha[3], scan[i]->ha[4], scan[i]->ha[5],
		scan[i]->gateway, scan[i]->self);
	}
	TELL_DUMP_FILE_NAME(dumpfilename);
	fclose(filedumpfile);
}

int ask_string(char *msg, char **buf) {
	size_t size = 0;

	*buf = NULL;
	printf("%s\n> ", msg);
	getline(buf, &size, stdin);
	if (*buf == NULL)
		{ ERROR_MALLOC(); return 1; }
	(*buf)[strlen(*buf) - 1] = 0;
	return 0;
}

int ask_index_list(nmap_r **scan, char **buf)
{
	size_t size = 0;
	char c;

	*buf = NULL;
	printf("\n%sChoose somes hosts from the list (comma separated if multiple):\n", SAMPLE_INFO);
	PRINT_SCAN_LIST(scan);
	printf("\n\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"R"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Return"ANSI_COLOR_RESET"\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"E"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Exit"ANSI_COLOR_RESET"\n\n"PROMPT);
	getline(buf, &size, stdin);
	if (*buf == NULL)
		{ ERROR_MALLOC(); return 1; }
	c = toupper(get_first_non_whitespace(*buf));
	if (c == 'E')
		return ACTION_EXIT;
	if (c == 'R')
		return ACTION_RETURN;
	return 0;
}

int change_ppm(struct arguments *arguments)
{
	char *buf = NULL;
	int newppm = 0;
	size_t size = 0;

	TELL_CHANGE_PPM_HEADER(arguments->ppm);
	getline(&buf, &size, stdin);
	sscanf(buf, "%d", &newppm);
	if (newppm < 0)
		{ ERROR_PACKET_PER_MINUTE(newppm); goto err; }
	arguments->ppm = newppm;
	free(buf);
	return 0;
err:
	if (buf)
		free(buf);
	return -1;
}

/* attack one, refresh, etc... */
int ask_action()
{
	int action;
	char buffer[0x40];

	ASK_ATTACK_TYPE();
	while (1) {
		fgets(buffer, 0x40, stdin); // should be replaced by getline no ?
		action = toupper(buffer[0]);
		if (action == '1' || action == '2'
		|| action == '3' || action == '4'
		|| action == '5' || action == '6'
		|| action == 'E' || action == 'S'
		|| action == 'L' || action == 'P'
		|| action == 'D' || action == 'G')
			break;
		WARNING_UNRECOGNIZED_CHAR_ASK(action);
		ASK_ATTACK_TYPE();
	}
	if (action == 'E')
		return ACTION_EXIT;
	if (action == 'P')
		return ACTION_CHANGE_PPM;
	if (action == 'S')
		return ACTION_SCAN;
	if (action == 'L')
		return ACTION_LIST;
	if (action == 'D')
		return ACTION_DUMP_NETWORK;
	if (action == 'G')
		return ACTION_LOAD_NETWORK;
	return action;
}

int ask_user_for_gateway()
{
	return 0;
}