/**
 * user-space PNA
 * This is the driver for the PNA software, it is process-level parallel
 * per interface.
 */

#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <time.h>
#include <pwd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>         /* the L2 protocols */

#include "pna.h"
#include "util.h"

#define ALARM_SLEEP     10   // seconds between stat printouts
#define DEFAULT_SNAPLEN 256  // big enough for all the headers
#define PROMISC_MODE    1    // give us everything

#define MAX_BUF         1024

pcap_t    *pd;
int verbose = 0;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define ENV_PNA_NETWORKS "PNA_NETWORKS"
#define DEFAULT_PNA_NETWORKS  "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

#define ENV_PNA_LOGDIR "PNA_LOGDIR"
#define DEFAULT_LOG_DIR  "./logs"
char *log_dir;
char *pcap_source_name = NULL;


/* PNA configuration parameters */
unsigned int pna_flow_entries = (1 << 23);
unsigned int pna_tables = 2;
unsigned int pna_bits = 16;

char pna_debug = false;
char pna_perfmon = 0;
char pna_flowmon = 1;
char pna_rtmon = false;

int pna_dtrie_init(void);
int pna_dtrie_deinit(void);
int pna_dtrie_build(char *networks_file);
int pna_dtrie_parse(char *networks, int network_id);

/**
 * handler to cleanup app
 */
void cleanup(void)
{
	static int called = 0;

	if (called) {
		return;
	}
	else {
		called = 1;
	}

	pcap_close(pd);
	pna_dtrie_deinit();
	pna_cleanup();
	exit(0);
}

void sigproc(int sig) {
	cleanup();
}

/**
 * periodic stats report for input/output numbers
 */
void stats_report(int sig) {
	print_stats(PCAP, pd, &startTime, numPkts, numBytes);
	alarm(ALARM_SLEEP);
	signal(SIGALRM, stats_report);
}

/**
 * This is the pcap callback hook that will grab the relevant info and pass
 * it on to the PNA software for handling
 */
void pkt_hook(u_char *device, const struct pcap_pkthdr *h, const u_char *p)
{
	// first packet we've seen, capture the time for stats
	if (numPkts == 0) {
		gettimeofday(&startTime, NULL);
	}

	// it appears to be an empty packet, skip it
	if (h->len == 0) {
		return;
	}

	// call the hook
	pna_hook(h->len, h->ts, p);

	// update stats
	numPkts++;
	numBytes += h->len;
}

/**
 * change the uid fomr current user to id for `username`
 */
void uid_to(const char *username) {
	struct passwd *pw = NULL;

	pw = getpwnam(username);
	if (!pw) {
		fprintf(stderr, "could not find username: '%s'\n", username);
		exit(1);
	}

	// initialize the target user's group memberships for this process
	if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
		fprintf(stderr, "could not init group list for '%s'\n", username);
		exit(1);
	}

	// set the group id of this process
	if (setgid(pw->pw_gid) != 0) {
		fprintf(stderr, "could not set group id for '%s' (gid: %u)\n",
				username, pw->pw_gid);
		exit(1);
	}

	// set the user id of this process
	if (setuid(pw->pw_uid) != 0) {
		fprintf(stderr, "could not set user id for '%s' (uid: %u)\n",
				username, pw->pw_uid);
		exit(1);
	}
}

/**
 * command line help
 */
void printHelp(void) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devpointer;

	printf("uPNA\n");
	printf("-h             Print help\n");
	printf("-i <device>    Device name\n");
	printf("-r <filename>  Read from file\n");
	printf("-o <output>    Write data to <output> directory\n");
	printf("-Z <username>  Change user ID to <username> as soon as possible\n");
	printf("-n <net_file>  File of networks to process\n");
	printf("-N <networks>  List of networks to process\n");
	printf("-f <entries>   Number of flow table entries (default %u)\n",
	       pna_flow_entries);
	printf("-v             Verbose mode\n");

	if (pcap_findalldevs(&devpointer, errbuf) == 0) {
		printf("\nAvailable devices (-i):\n");
		while (devpointer) {
			printf("- %s\n", devpointer->name);
			devpointer = devpointer->next;
		}
	}
}


/**
 * Add networks to monitor
 */
int add_networks(char *networks, int network_id)
{
	char buffer[MAX_BUF];
	int ret;
	char *network, *brkt;

	strncpy(buffer, networks, MAX_BUF);

	network = strtok_r(buffer, " ", &brkt);
	while (network) {
		network_id = network_id + 1;
		ret = pna_dtrie_parse(network, network_id);
		if (ret != 0) {
			exit(1);
		}
		network = strtok_r(NULL, " ", &brkt);
	}

	return network_id;
}


/**
 * Main driver
 */
int main(int argc, char **argv) {
	int c;
	char errbuf[PCAP_ERRBUF_SIZE];
	int promisc;
	int ret;
	char *listen_device = NULL;
	char *username = NULL;
	char *input_file = NULL;
	char *networks = NULL;
	int network_id = 0;

	startTime.tv_sec = 0;

	/* load some environment variables */
	log_dir = getenv(ENV_PNA_LOGDIR);
	if (!log_dir) {
		log_dir = DEFAULT_LOG_DIR;
	}

	/* initialize needed pna components */
	pna_init();
	pna_dtrie_init();

	while ((c = getopt(argc, argv, "o:hi:r:n:N:vf:Z:")) != '?') {
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			printHelp();
			exit(0);
			break;
		case 'o':
			log_dir = strdup(optarg);
			break;
		case 'i':
			listen_device = strdup(optarg);
			break;
		case 'r':
			input_file = strdup(optarg);
			break;
		case 'Z':
			username = strdup(optarg);
			break;
		case 'n':
			ret = pna_dtrie_build(optarg);
			if (ret != 0) {
				exit(1);
			}
			/* indicate that we loaded some networks */
			network_id = 1;
			break;
		case 'N':
			/* -N can be "10.0.0.0/8 172.16.0.0/12" or 
			 * multiple -N 10.0.0.0/8 -N 172.16.0.0/12 */
			network_id = add_networks(optarg, network_id);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'f':
			pna_flowmon = 1;
			if (atoi(optarg) != 0)
				pna_flow_entries = atoi(optarg);
			break;
		}
	}

	/* load some default networks to listen on (if none supplied) */
	if (network_id == 0) {
		networks = getenv(ENV_PNA_NETWORKS);
		if (!networks) {
			networks = DEFAULT_PNA_NETWORKS;
		}
		add_networks(networks, network_id);
	}


	if (listen_device != NULL && input_file != NULL) {
		printf("cannot specify both device and file\n");
		return -1;
	}
	else if (listen_device) {
		printf("Live capture from %s\n", listen_device);
		pd = pcap_open_live(
			listen_device, DEFAULT_SNAPLEN, PROMISC_MODE, 500, errbuf
		);
		pcap_source_name = listen_device;
	}
	else if (input_file) {
		printf("Reading file from %s\n", input_file);
		pd = pcap_open_offline(input_file, errbuf);
		pcap_source_name = basename(input_file);
	}
	else {
		printf("must specify device or file\n");
		return -1;
	}
	if (pd == NULL) {
		printf("pcap_open: %s\n", errbuf);
		return -1;
	}

	// handle Ctrl-C kindly
	signal(SIGINT, sigproc);
	atexit(cleanup);

	// if wanted, periodically print stat reports
	if (verbose) {
		signal(SIGALRM, stats_report);
		alarm(ALARM_SLEEP);
	}

	// if requested (and possible) drop privileges to specified user
	if (username != NULL && (getuid() == 0 || geteuid() == 0)) {
		if (verbose) {
			printf("dropping to user: %s\n", username);
		}
		uid_to(username);
	}

	// ...and go!
	pcap_loop(pd, -1, pkt_hook, NULL);

	return 0;
}
