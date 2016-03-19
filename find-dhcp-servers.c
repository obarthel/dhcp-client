/*
 * Find DHCP servers which respond to DISCOVER messages, collect
 * their responses and print them. Multiple responses by different
 * servers will be collected and reported, not just the first
 * response to arrive.
 *
 * The purpose of this command is to find rogue DHCP servers in the local network,
 * but it can also be used to check if there is any active DHCP server in the local
 * network in the first place.
 *
 * Based upon the "Simple DHCP Client" by Samuel Jacob (samueldotj@gmail.com)
 *
 * Adapted and rewritten by Olaf Barthel <obarthel at gmx dot net>
 * 2016-03-14
 *
 * Requires libpcap to build and link, and C99 support in the compiler/runtime
 * library. Builds and works correctly under Linux (Debian and CentOS tested)
 * and Mac OS X. GCC or clang are required to build this command, but if you
 * remove the __attribute__ annotations then any 'C' compiler with C99 support
 * should do, too.
 *
 * License : BSD
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif /* !__linux__ */
#include <netinet/in.h>
#include <netinet/ip.h>

#ifdef __linux__
/* This makes the 'struct udphdr' use the same
 * field names as used in the BSD header files.
 */
#define __FAVOR_BSD
#endif /* __linux__ */
#include <netinet/udp.h>

#include <ifaddrs.h>

#include <sys/time.h>

#include <stdbool.h>
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <setjmp.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <pcap.h>

/****************************************************************************/

#include "list_node.h"

/****************************************************************************/

/* 32 bit IPv4 address. */
typedef uint32_t ip4_t;

/****************************************************************************/

/* Combined IP and UDP headers, suitable for calculating
 * and verifying the UDP datagram checksum.
 */
struct udp_pseudo_header
{
	uint32_t	ih_zero1[2];	/* set to zero */
	uint8_t		ih_zero2;		/* set to zero */
	uint8_t		ih_pr;			/* protocol */
	uint16_t	ih_len;			/* protocol length */
	ip4_t		ih_src;			/* source internet address */
	ip4_t		ih_dst;			/* destination internet address */
	
	uint16_t	uh_sport;		/* source port */
	uint16_t	uh_dport;		/* destination port */
	int16_t		uh_ulen;		/* udp length */
	uint16_t	uh_sum;			/* udp checksum */
};

/****************************************************************************/

/* Source: http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm
 *
 * This is actually the BOOTP packet (RFC 951) with the
 * vendor information format stored in the first four
 * octets of the vendor specific area (RFC 1048).
 */
typedef struct
{
	uint8_t		opcode;			/* Packet op code / message type */
	uint8_t		htype;			/* Hardware address type */
	uint8_t		hlen;			/* Hardware address length */
	uint8_t		hops;
	uint32_t	xid;			/* Transaction ID */
	uint16_t	secs;
	uint16_t	flags;
	ip4_t		ciaddr;			/* Client IP address; client sets this to 0 */
	ip4_t		yiaddr;			/* Filled in by server if client doesn't know its own address */
	ip4_t		siaddr;			/* Server IP address */
	ip4_t		giaddr;			/* Gateway IP address */
	uint8_t		chaddr[16];		/* Client hardware address */
	char		sname[64];		/* Optional server host name */
	char		file[128];		/* Boot file name */
	uint32_t	magic_cookie;	/* Vendor information format (RFC 1048). */
	uint8_t		vend[0];		/* Vendor-specific area; these should be 60 octets minimum. */
} bootp_t;

/****************************************************************************/

/* This should be in bootp_t.opcode (RFC 951). */
enum
{
	BOOTREQUEST=1,
	BOOTREPLY=2
};

/****************************************************************************/

/* This goes into bootp_t.htype (RFC 951). */
#define BOOTP_HARDWARE_TYPE_10_ETHERNET	1

/****************************************************************************/

/* Selected BOOTP/DHCP option types (RFC 2132, etc.). */
enum
{
	OPTION_TYPE_PAD=0,
	OPTION_TYPE_SUBNET_MASK=1,
	OPTION_TYPE_GATEWAY=3,
	OPTION_TYPE_DNS=6,
	OPTION_TYPE_DOMAIN_NAME=15,
	OPTION_TYPE_INTERFACE_MTU=26,
	OPTION_TYPE_BROADCAST_ADDRESS=28,
	OPTION_TYPE_PERFORM_ROUTER_DISCOVERY=31,
	OPTION_TYPE_STATIC_ROUTE=33,
	OPTION_TYPE_NTP_SERVERS=42,
	OPTION_TYPE_NETBIOS_OVER_TCP_IP_NAME_SERVER=44,
	OPTION_TYPE_NETBIOS_OVER_TCP_IP_NODE_TYPE=46,
	OPTION_TYPE_NETBIOS_OVER_TCP_IP_SCOPE=47,
	OPTION_TYPE_IP_ADDRESS_LEASE_TIME=51,
	OPTION_TYPE_DHCP_MESSAGE_TYPE=53,
	OPTION_TYPE_SERVER_IDENTIFIER=54,
	OPTION_TYPE_PARAMETER_REQUEST_LIST=55,
	OPTION_TYPE_MESSAGE=56,
	OPTION_TYPE_MAXIMUM_DHCP_MESSAGE_SIZE=57,
	OPTION_TYPE_RENEWAL_TIME=58,
	OPTION_TYPE_REBINDING_TIME=59,
	OPTION_TYPE_LDAP_URL=95,
	OPTION_TYPE_AUTO_CONFIGURE=116,
	OPTION_TYPE_DOMAIN_SEARCH=119,
	OPTION_TYPE_CLASSLESS_STATIC_ROUTE=121,
	OPTION_TYPE_PROXY_AUTODISCOVERY=252,
	OPTION_TYPE_END=255
};

/****************************************************************************/

/* DHCP message types (RFC 1531, etc.). */
enum
{
	MESSAGE_TYPE_DISCOVER=1,
	MESSAGE_TYPE_OFFER=2,
	MESSAGE_TYPE_REQUEST=3,
	MESSAGE_TYPE_DECLINE=4,
	MESSAGE_TYPE_ACK=5,
	MESSAGE_TYPE_NAK=6,
	MESSAGE_TYPE_RELEASE=7,
	MESSAGE_TYPE_INFORM=8
};

/****************************************************************************/

/* DHCP server and client port numbers. Actually, these
 * are really the BOOTP port numbers (RFC 951). We use
 * these values only as fallbacks if the "bootp" entries
 * are missing from the network database.
 */
enum
{
	DEFAULT_BOOTP_SERVER_PORT=67,
	DEFAULT_BOOTP_CLIENT_PORT=68
};

/****************************************************************************/

/* Magic cookie stored in the vendor-specific area (RFC 1048, etc.),
 * identifying the contents and structure of the data following
 * it. */
#define DHCP_MAGIC_COOKIE 0x63825363

/****************************************************************************/

/* Stores a key and its associated value string. */
struct kv_node
{
	struct Node	node;
	char *		key;
	char *		value;
};

/****************************************************************************/

/* Store DHCP server response data; the server is uniquely identified
 * by the pair of its IPv4 and MAC address.
 */
struct dhcp_server_response_data
{
	struct Node		node;

	struct timeval	stamp;
	uint8_t			server_ipv4_address[4];
	uint8_t			server_mac_address[ETHER_ADDR_LEN];

	struct List		dhcp_response;
	struct List		dhcp_option;
};

/****************************************************************************/

/* Generic Ethernet broadcast group address. */
const uint8_t broadcast_mac_address[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* This is where the MAC address of the interface will be stored which the
 * DHCP message will be sent through.
 */
uint8_t client_mac_address[ETHER_ADDR_LEN];

/****************************************************************************/

/* Filled in with the BOOTP server and client port numbers. */
uint16_t dhcp_server_port;
uint16_t dhcp_client_port;

/****************************************************************************/

struct List dhcp_server_response_list;
uint32_t transaction_id;
pcap_t * pcap_handle;
const char * interface_name;
jmp_buf alarm_jmp_buf;
const char * command_name;

/****************************************************************************/

/* Global options, as defined by the command line parameters. */
int opt_max_response_count = 0;
int opt_min_response_count = 0;
int opt_timeout = 5;
bool opt_broadcast = false;
bool opt_audible = false;
bool opt_verbose = false;
bool opt_quiet = false;
bool opt_ignore_checksums = false;

/****************************************************************************/

/* Prints the collected DHCP server responses, along with the DHCP
 * options transmitted.
 */
static void
print_dhcp_server_data(void)
{
	struct dhcp_server_response_data * data;
	struct kv_node * kvn;
	const struct tm * converted_time;
	char date_time_string[24];
	char microsecond_string[10];
	char time_zone_string[8];
	bool printed = false;

	for(data = (struct dhcp_server_response_data *)get_list_head(&dhcp_server_response_list) ;
		data != NULL ;
		data = (struct dhcp_server_response_data *)get_next_node(&data->node))
	{
		if(printed)
			printf("\n");

		/* Convert the date and time at which the DHCP server response
		 * arrived into ISO 8601 format, which covers microsecond
		 * accuracy.
		 */
		converted_time = localtime(&data->stamp.tv_sec);

		/* Date and time without seconds. */
		strftime(date_time_string,sizeof(date_time_string),"%Y-%m-%dT%H:%M",converted_time);

		/* Seconds with fractions (microseconds). */
		snprintf(microsecond_string,sizeof(microsecond_string),"%02.6g",
			(double)converted_time->tm_sec + ((double)data->stamp.tv_usec) / 1000000.0);

		/* Just one significant digit? This should not happen, but it does :-( */
		if(microsecond_string[1] == '.')
		{
			/* Prepend a leading '0'. */
			memmove(&microsecond_string[1],microsecond_string,strlen(microsecond_string)+1);
			microsecond_string[0] = '0';
		}

		/* Time zone offset. */
		strftime(time_zone_string,sizeof(time_zone_string),"%z",converted_time);

		printf("time-received=%s:%s%s\n",date_time_string,microsecond_string,time_zone_string);

		/* General response information. */
		for(kvn = (struct kv_node *)get_list_head(&data->dhcp_response) ;
			kvn != NULL ;
			kvn = (struct kv_node *)get_next_node(&kvn->node))
		{
			printf("%s=%s\n",kvn->key,kvn->value);
		}

		/* BOOTP/DHCP options. */
		for(kvn = (struct kv_node *)get_list_head(&data->dhcp_option) ;
			kvn != NULL ;
			kvn = (struct kv_node *)get_next_node(&kvn->node))
		{
			printf("option-%s=%s\n",kvn->key,kvn->value);
		}

		printed = true;
	}
}

/****************************************************************************/

/* Check if we already keep track of a specific DHCP server, which uses
 * a known combination of IPv4 address and MAC address. Returns NULL
 * if no such DHCP server has been recorded yet.
 */
static struct dhcp_server_response_data *
find_dhcp_server_data(const uint8_t * server_ipv4_address, const uint8_t * server_mac_address)
{
	struct dhcp_server_response_data * result = NULL;
	struct dhcp_server_response_data * data;

	for(data = (struct dhcp_server_response_data *)get_list_head(&dhcp_server_response_list) ;
		data != NULL ;
		data = (struct dhcp_server_response_data *)get_next_node(&data->node))
	{
		if(memcmp(data->server_ipv4_address,server_ipv4_address,sizeof(data->server_ipv4_address)) == 0 &&
		   memcmp(data->server_mac_address,server_mac_address,sizeof(data->server_mac_address)) == 0)
		{
			result = data;
			break;
		}
	}

	return(result);
}

/****************************************************************************/

/* Add a record for a DHCP server with given IPv4 address and MAC address. Returns
 * NULL if not enough memory available.
 */
static struct dhcp_server_response_data *
create_dhcp_server_data(const uint8_t * server_ipv4_address, const uint8_t * server_mac_address)
{
	struct dhcp_server_response_data * result = NULL;
	struct dhcp_server_response_data * data;

	data = calloc(1,sizeof(*data));
	if(data == NULL)
		goto out;

	gettimeofday(&data->stamp, NULL);

	memmove(data->server_ipv4_address,server_ipv4_address,sizeof(data->server_ipv4_address));
	memmove(data->server_mac_address,server_mac_address,sizeof(data->server_mac_address));

	new_list(&data->dhcp_response);
	new_list(&data->dhcp_option);

	add_node_to_list_tail(&dhcp_server_response_list, &data->node);

	result = data;
	data = NULL;

out:

	return(result);
}

/****************************************************************************/

/* Release memory allocated by create_kv_node(). This is safe to call
 * even if create_kv_node() failed.
 */
static void
delete_kv_node(struct kv_node * kvn)
{
	if(kvn != NULL)
	{
		if(kvn->key != NULL)
			free(kvn->key);

		if(kvn->value != NULL)
			free(kvn->value);

		free(kvn);
	}
}

/****************************************************************************/

/* Allocate memory for a key-value record, with the key value
 * generated from a printf() style format spec. Returns NULL
 * in case of error.
 */
static struct kv_node *
create_kv_node(const char * key,const char * string_format,va_list args)
{
	struct kv_node * result = NULL;
	struct kv_node * kvn;

	kvn = calloc(1,sizeof(*kvn));
	if(kvn == NULL)
		goto out;

	kvn->key = strdup(key);
	if(kvn->key == NULL)
		goto out;

	if(vasprintf(&kvn->value,string_format,args) < 0)
		goto out;

	result = kvn;
	kvn = NULL;

out:

	if(kvn != NULL)
		delete_kv_node(kvn);

	return(result);
}

/****************************************************************************/

/* Remember a DHCP server response, with given name. The response value is
 * stored as a string, using the printf() style formatting provided.
 */
struct kv_node * __attribute__ ((format (printf, 3, 4)))
add_dhcp_response(struct dhcp_server_response_data * data,const char * key,const char * string_format,...)
{
	struct kv_node * result = NULL;
	struct kv_node * kvn;
	va_list args;

	va_start(args, string_format);
	kvn = create_kv_node(key,string_format,args);
	va_end(args);

	if(kvn == NULL)
		goto out;

	add_node_to_list_tail(&data->dhcp_response, &kvn->node);

	result = kvn;

out:

	return(result);
}

/****************************************************************************/

/* Remember a DHCP option, with given option name. The option value is
 * stored as a string, using the printf() style formatting provided.
 */
struct kv_node * __attribute__ ((format (printf, 3, 4)))
add_dhcp_option(struct dhcp_server_response_data * data,const char * key,const char * string_format,...)
{
	struct kv_node * result = NULL;
	struct kv_node * kvn;
	va_list args;

	va_start(args, string_format);
	kvn = create_kv_node(key,string_format,args);
	va_end(args);

	if(kvn == NULL)
		goto out;

	add_node_to_list_tail(&data->dhcp_option, &kvn->node);

	result = kvn;

out:

	return(result);
}

/****************************************************************************/

/*
 * Get MAC address of given link(dev_name)
 */
static int
get_mac_address_and_mtu(const char *dev_name, uint8_t *mac_address, int * mtu)
{
	int result = -1;
	struct ifreq ifr;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(fd == -1)
		goto out;

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name, dev_name, sizeof(ifr.ifr_name));

	if(ioctl(fd, SIOCGIFMTU, &ifr) == -1)
		goto out;

	(*mtu) = ifr.ifr_mtu;

	#if defined(__linux__)
	{
		memset(&ifr,0,sizeof(ifr));
		strncpy(ifr.ifr_name, dev_name, sizeof(ifr.ifr_name));

		if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
			goto out;

		memmove(mac_address, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	}
	#else
	{
		struct ifaddrs *ifap, *p;

		if (getifaddrs(&ifap) != 0)
			goto out;

		for (p = ifap ; p != NULL ; p = p->ifa_next)
		{
			/* Check the device name */
			if (strcmp(p->ifa_name, dev_name) == 0 && p->ifa_addr->sa_family == AF_LINK)
			{
				const struct sockaddr_dl * sdp;

				sdp = (struct sockaddr_dl *)p->ifa_addr;
				memmove(mac_address, sdp->sdl_data + sdp->sdl_nlen, ETHER_ADDR_LEN);

				break;
			}
		}

		freeifaddrs(ifap);
	}
	#endif

	result = 0;

out:

	if(fd != -1)
		close(fd);

	return(result);
}

/****************************************************************************/

/*
 * Return checksum for the given data.
 * Copied from FreeBSD
 */
static unsigned short
in_cksum(const void *_addr, int nleft)
{
	const uint16_t *w = _addr;
	int sum = 0;
	uint16_t answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		*(uint8_t *)&answer = *(const uint8_t *)w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;	/* truncate to 16 bits */

	return (answer);
}

/****************************************************************************/

/* Search the DHCP options for the DHCP message type and then return it.
 * Returns -1 if no DHCP message type could be found.
 */
static int
get_dhcp_message_type(const uint8_t * vendor_options,int vendor_options_length)
{
	int option_type,option_length;
	int result = -1;
	int pos;

	for(pos = 0 ; pos < vendor_options_length ; (void)NULL)
	{
		option_type = vendor_options[pos++];

		/* Padding is simply skipped. */
		if(option_type == OPTION_TYPE_PAD)
			continue;

		/* We stop at the end marker, or if we reach the end of the option buffer. */
		if(option_type == OPTION_TYPE_END || pos == vendor_options_length)
			break;

		/* We stop when we reach the end of the option buffer. */
		option_length = vendor_options[pos++];
		if(pos == vendor_options_length)
			break;

		if(option_type == OPTION_TYPE_DHCP_MESSAGE_TYPE)
		{
			result = vendor_options[pos];
			break;
		}

		pos += option_length;
	}

	return(result);
}

/****************************************************************************/

/* Decode classless static route information (RFC 3442) into a text buffer. */
static int decode_classless_static_route(const uint8_t * option_data, int option_length,
	char * text_buffer, size_t text_buffer_size)
{
	int num_destination_octets;
	uint8_t destination_octets[4];
	uint8_t route_octets[4];
	int num_routes_decoded = 0;
	char decoded_route_buffer[256];
	int decoded_route_buffer_len;
	size_t len = 0;
	int result = -1;
	int pos;
	int i;

	/* One off for NUL-termination. */
	if(text_buffer_size > 0)
		text_buffer_size--;

	for(pos = 0 ; pos < option_length ; )
	{
		/* First octet states subnet mask. This must
		 * be a value in the range 0-4.
		 */
		num_destination_octets = option_data[pos++];
		if(num_destination_octets > 4)
			goto out;

		/* Number of octets to follow must be in the
		 * buffer provided, not beyond it.
		 */
		if(pos + num_destination_octets > option_length)
			goto out;

		/* Copy the significant octets, then fill up
		 * the remainder with zeroes.
		 */
		for(i = 0 ; i < num_destination_octets ; i++)
			destination_octets[i] = option_data[pos++];

		for( ; i < 4 ; i++)
			destination_octets[i] = 0;

		/* The router address must be in the buffer. */
		if(pos + 4 > option_length)
			goto out;

		for(i = 0 ; i < 4 ; i++)
			route_octets[i] = option_data[pos++];

		/* No destination given? Then decode only the router address. */
		if (num_destination_octets == 0)
		{
			decoded_route_buffer_len = snprintf(decoded_route_buffer,sizeof(decoded_route_buffer),
				"%u.%u.%u.%u",
				route_octets[0],route_octets[1],
				route_octets[2],route_octets[3]);
		}
		/* 32 bit subnet mask given? Then omit the subnet mask from the decoded output. */
		else if (num_destination_octets == 4)
		{
			decoded_route_buffer_len = snprintf(decoded_route_buffer,sizeof(decoded_route_buffer),
				"%u.%u.%u.%u -> %u.%u.%u.%u",
				destination_octets[0],destination_octets[1],
				destination_octets[2],destination_octets[3],
				route_octets[0],route_octets[1],
				route_octets[2],route_octets[3]);
		}
		/* Default case: decode destination address and subnet size, as well
		 * as the router address.
		 */
		else
		{
			decoded_route_buffer_len = snprintf(decoded_route_buffer,sizeof(decoded_route_buffer),
				"%u.%u.%u.%u/%d -> %u.%u.%u.%u",
				destination_octets[0],destination_octets[1],
				destination_octets[2],destination_octets[3],
				num_destination_octets * 8,
				route_octets[0],route_octets[1],
				route_octets[2],route_octets[3]);
		}

		assert( decoded_route_buffer_len > 0 );

		/* If more than one single destination/subnet/router
		 * was provided, separate the output by adding a
		 * command and a blank space.
		 */
		if(len > 0)
		{
			/* Buffer overflow? */
			if(len + 2 > text_buffer_size)
				goto out;

			text_buffer[len++] = ',';
			text_buffer[len++] = ' ';
		}

		/* Buffer overflow? */
		if(len + decoded_route_buffer_len > text_buffer_size)
			goto out;

		memmove(&text_buffer[len], decoded_route_buffer, decoded_route_buffer_len);

		len += decoded_route_buffer_len;

		text_buffer[len] = '\0';

		num_routes_decoded++;
	}

	text_buffer[len] = '\0';

	result = num_routes_decoded;

 out:

	return(result);
}

/****************************************************************************/

/* Decode static route information (RFC 1533) into a text buffer. */
static int decode_static_route(const uint8_t * option_data, int option_length,
	char * text_buffer, size_t text_buffer_size)
{
	int num_routes;
	uint8_t destination_octets[4];
	uint8_t route_octets[4];
	int num_routes_decoded = 0;
	char decoded_route_buffer[256];
	int decoded_route_buffer_len;
	size_t len = 0;
	int result = -1;
	int pos;
	int i;

	/* One off for NUL-termination. */
	if(text_buffer_size > 0)
		text_buffer_size--;

	for(pos = 0 ; pos < option_length ; )
	{
		num_routes = option_data[pos++];
		if(num_routes == 0)
			break;

		/* Number of octets to follow must be in the
		 * buffer provided, not beyond it.
		 */
		if(pos + 4 + 4 > option_length)
			goto out;

		for(i = 0 ; i < 4 ; i++)
			destination_octets[i] = option_data[pos++];

		for(i = 0 ; i < 4 ; i++)
			route_octets[i] = option_data[pos++];

		decoded_route_buffer_len = snprintf(decoded_route_buffer,sizeof(decoded_route_buffer),
			"%u.%u.%u.%u -> %u.%u.%u.%u",
			destination_octets[0],destination_octets[1],
			destination_octets[2],destination_octets[3],
			route_octets[0],route_octets[1],
			route_octets[2],route_octets[3]);

		assert( decoded_route_buffer_len > 0 );

		/* If more than one single destination/subnet/router
		 * was provided, separate the output by adding a
		 * command and a blank space.
		 */
		if(len > 0)
		{
			/* Buffer overflow? */
			if(len + 2 > text_buffer_size)
				goto out;

			text_buffer[len++] = ',';
			text_buffer[len++] = ' ';
		}

		/* Buffer overflow? */
		if(len + decoded_route_buffer_len > text_buffer_size)
			goto out;

		memmove(&text_buffer[len], decoded_route_buffer, decoded_route_buffer_len);

		len += decoded_route_buffer_len;

		text_buffer[len] = '\0';

		num_routes_decoded++;
	}

	text_buffer[len] = '\0';

	result = num_routes_decoded;

out:

	return(result);
}

/****************************************************************************/

/* Convert the number of seconds given for lease time and renewal/rebinding
 * interval into more than just a single number, detailing minutes/hours/days.
 */
static void
convert_seconds_to_readable_form(uint32_t seconds,char * buffer,size_t buffer_size)
{
	if(seconds < 60)
	{
		assert( buffer_size > 0 );
		
		strcpy(buffer,"");
	}
	else if (seconds < 60 * 60)
	{
		int minutes = seconds / 60;

		snprintf(buffer,buffer_size,minutes > 1 ? " (%u:%02u minutes)" : " (%u:%02u minute)",
			minutes,
			seconds % 60);
	}
	else if (seconds < 24 * 60 * 60)
	{
		int hours = seconds / (60 * 60);

		snprintf(buffer,buffer_size,hours > 1 ? " (%u:%02u:%02u hours)" : " (%u:%02u:%02u hour)",
			hours,
			(seconds / 60) % 60,
			seconds % 60);
	}
	else
	{
		int days = seconds / (24 * 60 * 60);

		snprintf(buffer,buffer_size,days > 1 ? " (%u:%02u:%02u:%02u days)" : " (%u:%02u:%02u:%02u day)",
			days,
			(seconds / (60 * 60)) % 24,
			(seconds / 60) % 60,
			seconds % 60);
	}
}

/****************************************************************************/

/* Search for DHCP options of a specific type, aggregating their data into
 * a single consecutive memory buffer. Returns true if any DHCP options
 * could be found and a buffer was allocated for them, false otherwise.
 * The buffer allocated must be freed eventually.
 *
 * Aggregated option data is described in RFC 3396 ("Encoding long options
 * in the Dynamic Host Configuration Protocol (DHCPv4)").
 */
static bool
fill_aggregate_buffer_from_option(const uint8_t * vendor_options,int vendor_options_length,
	int aggregate_option_type, uint8_t ** aggregate_buffer_ptr,size_t * aggregate_buffer_size_ptr)
{
	bool option_data_found = false;
	uint8_t * aggregate_buffer = NULL;
	size_t required_size = 0;
	int option_type;
	int option_length;
	int output_pos;
	int read_pos;
	
	assert( 0 < aggregate_option_type && aggregate_option_type < 255 );
	assert( aggregate_buffer_ptr != NULL );
	assert( aggregate_buffer_size_ptr != NULL );

	/* Find out how much memory is required to store all
	 * the data for a specific option type.
	 */
	for(read_pos = 0 ; read_pos < vendor_options_length ; (void)NULL)
	{
		option_type = vendor_options[read_pos++];

		/* Skip the padding octet. */
		if(option_type == OPTION_TYPE_PAD)
			continue;

		/* Stop at the end marker, or the end of the options buffer. */
		if(option_type == OPTION_TYPE_END || read_pos == vendor_options_length)
			break;

		option_length = vendor_options[read_pos++];

		/* Stop at the end of the options buffer. */
		if(read_pos == vendor_options_length)
			break;
		
		if(option_type == aggregate_option_type)
			required_size += option_length;
	}

	/* No option data found? Then we have failed... */
	if(required_size == 0)
		goto out;

	/* Allocate memory for storing the aggregated data in.
	 * The buffer address and how much memory was allocated
	 * will be provided to the caller.
	 */
	aggregate_buffer = malloc(required_size);
	if(aggregate_buffer == NULL)
		goto out;
	
	(*aggregate_buffer_ptr) = aggregate_buffer;
	(*aggregate_buffer_size_ptr) = required_size;
	
	for(read_pos = output_pos = 0 ; read_pos < vendor_options_length ; (void)NULL)
	{
		option_type = vendor_options[read_pos++];

		/* Skip the padding octet. */
		if(option_type == OPTION_TYPE_PAD)
			continue;

		/* Stop at the end marker, or the end of the options buffer. */
		if(option_type == OPTION_TYPE_END || read_pos == vendor_options_length)
			break;

		option_length = vendor_options[read_pos++];

		/* Stop at the end of the options buffer. */
		if(read_pos == vendor_options_length)
			break;
		
		if(option_type == aggregate_option_type)
		{
			assert( output_pos + option_length <= (int)required_size );
			
			memmove(&aggregate_buffer[output_pos],&vendor_options[read_pos],option_length);

			read_pos += option_length;
			output_pos += option_length;
		}
	}
	
	option_data_found = true;
	
 out:
	
	return(option_data_found);
}

/****************************************************************************/

/* Find out how much space is required for storing a complete,
 * encoded domain name. The name either ends with a root marker
 * or a compression pointer (RFC 1035, section 4.1.4). Returns
 * number of octets used or 0 for buffer overflow/encoding
 * error.
 */
static size_t
get_domain_name_size(const uint8_t * buffer,size_t buffer_size)
{
	int length,compression;
	size_t result = 0;
	size_t pos;
	
	for(pos = 0 ; pos < buffer_size ; (void)NULL)
	{
		length = buffer[pos++];
		if(length == 0)
			break;

		/* A label begins with a length field which
		 * could also be a compression pointer.
		 */
		compression = length & 0xc0;

		/* Is this a length field? */
		if (compression == 0)
		{
			/* Check for buffer overflow. */
			if(pos + length > buffer_size)
				goto out;

			pos += length;
		}
		/* Is this a compression pointer? */
		else if (compression == 0xc0)
		{
			/* Check for buffer overflow. */
			if(pos == buffer_size)
				goto out;

			/* Domain name continues where the
			 * compression pointer leads to.
			 */
			pos++;
			break;
		}
		/* Undefined encoding scheme. */
		else
		{
			goto out;
		}
	}

	result = pos;

 out:

	return(result);
}

/****************************************************************************/

/* Decode a domain name stored in a DNS record, decompressing it as
 * necessary (RFC 1035, section 4.1.4). Returns the length of the
 * decoded domain name or 0 for decoding error.
 */
static size_t
decode_domain_name(const uint8_t * input_buffer,size_t input_buffer_size,size_t input_pos,
	char * output_buffer,size_t output_buffer_size)
{
	int length,compression;
	size_t output_pos = 0;
	size_t result = 0;

	assert( output_buffer_size > 0 );
	
	while(input_pos < input_buffer_size)
	{
		length = input_buffer[input_pos++];
		if(length == 0)
			break;
		
		/* A label begins with a length field which
		 * could also be a compression pointer.
		 */
		compression = length & 0xc0;

		/* Is this a length field? */
		if (compression == 0)
		{
			/* Check for buffer overflow. */
			if(input_pos + length > input_buffer_size)
				goto out;

			/* Append the label to the output buffer if there is room. */
			if(output_pos + length + 1 < output_buffer_size)
			{
				/* Add the label separator if there already is a
				 * label in the output buffer.
				 */
				if(output_pos > 0)
					output_buffer[output_pos++] = '.';

				memmove(&output_buffer[output_pos],&input_buffer[input_pos],length);
				output_pos += length;
			}
			
			input_pos += length;
		}
		/* Is this a compression pointer? */
		else if (compression == 0xc0)
		{
			size_t pointer;
			
			/* Check for buffer overflow. */
			if(input_pos == input_buffer_size)
				goto out;
			
			pointer = ((length & ~0xc0) << 8) | input_buffer[input_pos++];
			
			/* Check for buffer overflow. */
			if(pointer >= input_buffer_size)
				goto out;

			/* Domain name continues where the compression
			 * pointer leads.
			 */
			input_pos = pointer;
		}
		/* Undefined encoding scheme. */
		else
		{
			goto out;
		}
	}

	assert( output_pos < output_buffer_size );
	output_buffer[output_pos] = '\0';

	result = output_pos;

 out:
	
	return(result);
}

/****************************************************************************/

/* Decode DHCP option 119 (Domain search, RFC 3397). The domain data may
 * be broken up into several DHCP data options (RFC 3396) which first
 * need to be aggregated. Returns true if the data could be decoded,
 * false otherwise.
 */
static bool
decode_domain_search(const uint8_t * vendor_options,int vendor_options_length,
	int aggregate_option_type,char * buffer,size_t buffer_size)
{
	/* The maximum length of a domain name, including "." separators,
	 * would be 255 characters (RFC 2181, section 11 "Name syntax").
	 * Space is reserved for the terminating NUL byte, too.
	 */
	char domain_name_buffer[256];
	size_t domain_name_length;
	uint8_t * aggregate_buffer = NULL;
	size_t aggregate_buffer_size = 0;
	bool found = false;
	size_t buffer_pos = 0;
	size_t pos;
	size_t encoded_domain_size;

	assert( buffer != NULL );
	assert( buffer_size > 0 );

	/* Aggregate all option 119 data. */
	if(!fill_aggregate_buffer_from_option(vendor_options,vendor_options_length,
			aggregate_option_type,&aggregate_buffer,&aggregate_buffer_size))
		goto out;

	/* Process the aggregated data, decoding each domain name stored. */
	for(pos = 0 ; pos < aggregate_buffer_size ; pos += encoded_domain_size)
	{
		/* How much room will this encoded domain name take up? */
		encoded_domain_size = get_domain_name_size(&aggregate_buffer[pos],aggregate_buffer_size - pos);
		if(encoded_domain_size == 0)
			break;

		/* Attempt to decode this domain name. */
		domain_name_length = decode_domain_name(aggregate_buffer,aggregate_buffer_size,pos,
			domain_name_buffer,sizeof(domain_name_buffer));

		if(domain_name_length > 0)
		{
			/* If there is more than one domain name in the output buffer
			 * already, add a separator.
			 */
			if(buffer_pos > 0 && buffer_pos + 2 < buffer_size)
			{
				buffer[buffer_pos++] = ',';
				buffer[buffer_pos++] = ' ';
			}

			/* Add the decoded domain name, if there is stil room. */
			if(buffer_pos + domain_name_length < buffer_size)
			{
				memmove(&buffer[buffer_pos],domain_name_buffer,domain_name_length);
				buffer_pos += domain_name_length;
			}
		}
	}
	
	found = true;
	
 out:

	/* Provide NUL termination for the output buffer. */
	if(buffer_pos < buffer_size)
		buffer[buffer_pos] = '\0';

	/* Free the memory which we allocated for the
	 * aggregated option 119 data.
	 */
	if(aggregate_buffer != NULL)
		free(aggregate_buffer);

	return(found);
}

/****************************************************************************/

/*
 * This function will be called for any incoming DHCP responses
 */
static void
dhcp_input(const struct ether_header * eframe,
	const struct ip * ip_packet,
	const struct udphdr * udp_packet __attribute__((unused)),
	const bootp_t * dhcp,
	uint32_t transaction_id,
	int length)
{
	uint8_t ignore_option[256 / 8];
	ip4_t server_address;
	ip4_t ipv4_address;
	const uint8_t * vendor_options;
	int vendor_options_length;
	int pos;
	uint8_t server_ipv4_address[4];
	char text_buffer[1500];
	int option_type,option_length;

	/* We copy the option data to a 32 bit word-aligned
	 * buffer because we may need to access 32 bit words
	 * inside it and we cannot expect the option data to
	 * be aligned appropriately.
	 */
	uint32_t aligned_buffer[256 / sizeof(uint32_t)+1];
	uint8_t * option_data = (uint8_t *)aligned_buffer;
	struct dhcp_server_response_data * server_data;

	/* We ignore no vendor option yet. */
	memset(ignore_option,0,sizeof(ignore_option));

	vendor_options = dhcp->vend;
	vendor_options_length = length - offsetof(bootp_t,vend);

	/* This should be a DHCP server response, the transaction number must match
	 * the request we made and DHCP server should have responded with an
	 * offer.
	 */
	if (dhcp->opcode != BOOTREPLY || ntohl(dhcp->magic_cookie) != DHCP_MAGIC_COOKIE ||
		ntohl(dhcp->xid) != transaction_id ||
		get_dhcp_message_type(vendor_options,vendor_options_length) != MESSAGE_TYPE_OFFER)
	{
		return;
	}

	/* Ring the bell for each response? */
	if(opt_audible)
	{
		/* BEL = Ctrl+G */
		fputc('G' & 0x1F,stderr);

		/* stderr should be unbuffered, but you never know... */
		fflush(stderr);
	}

	server_address = ntohl(ip_packet->ip_src.s_addr);

	server_ipv4_address[0] = (server_address >> 24) & 0xff;
	server_ipv4_address[1] = (server_address >> 16) & 0xff;
	server_ipv4_address[2] = (server_address >> 8) & 0xff;
	server_ipv4_address[3] = server_address & 0xff;

	/* We only store one response per server. Do we already have
	 * a record of this one? If so, ignore its response.
	 */
	server_data = find_dhcp_server_data(server_ipv4_address, eframe->ether_shost);
	if(server_data != NULL)
	{
		if(!opt_quiet)
		{
			fprintf(stderr,"%s: Duplicate response from DHCP server at "
				"IPv4 address %u.%u.%u.%u/"
				"MAC address %02x:%02x:%02x:%02x:%02x:%02x ignored.\n",
				command_name,
				server_ipv4_address[0],server_ipv4_address[1],
				server_ipv4_address[2],server_ipv4_address[3],
				eframe->ether_shost[0], eframe->ether_shost[1], eframe->ether_shost[2],
				eframe->ether_shost[3], eframe->ether_shost[4], eframe->ether_shost[5]);
		}

		return;
	}

	/* Register a new server response. */
	server_data = create_dhcp_server_data(server_ipv4_address, eframe->ether_shost);
	if(server_data == NULL)
	{
		if(!opt_quiet)
		{
			fprintf(stderr,"%s: Not enough memory to record response from DHCP server at "
				"IPv4 address %u.%u.%u.%u/"
				"MAC address %02x:%02x:%02x:%02x:%02x:%02x.\n",
				command_name,
				server_ipv4_address[0],server_ipv4_address[1],
				server_ipv4_address[2],server_ipv4_address[3],
				eframe->ether_shost[0], eframe->ether_shost[1], eframe->ether_shost[2],
				eframe->ether_shost[3], eframe->ether_shost[4], eframe->ether_shost[5]);
		}

		return;
	}

	add_dhcp_response(server_data,"network-interface","%s (%02x:%02x:%02x:%02x:%02x:%02x)",
		interface_name,
		client_mac_address[0], client_mac_address[1], client_mac_address[2],
		client_mac_address[3], client_mac_address[4], client_mac_address[5]);

	/* The server name, if not empty, should be NUL-terminated. We cannot
	 * assume that it will be, which is why we add another NUL termination.
	 */
	memmove(text_buffer, dhcp->sname, sizeof(dhcp->sname));
	text_buffer[sizeof(dhcp->sname)] = '\0';

	if(text_buffer[0] != '\0')
		add_dhcp_response(server_data,"server-name","\"%s\"",text_buffer);

	add_dhcp_response(server_data,"server-ipv4-address","%u.%u.%u.%u",
		server_ipv4_address[0],server_ipv4_address[1],
		server_ipv4_address[2],server_ipv4_address[3]);

	add_dhcp_response(server_data,"server-mac-address","%02x:%02x:%02x:%02x:%02x:%02x",
		eframe->ether_shost[0], eframe->ether_shost[1], eframe->ether_shost[2],
		eframe->ether_shost[3], eframe->ether_shost[4], eframe->ether_shost[5]);

	add_dhcp_response(server_data,"destination-mac-address","%02x:%02x:%02x:%02x:%02x:%02x (%s)",
		eframe->ether_dhost[0], eframe->ether_dhost[1], eframe->ether_dhost[2],
		eframe->ether_dhost[3], eframe->ether_dhost[4], eframe->ether_dhost[5],
		memcmp(eframe->ether_dhost,broadcast_mac_address,ETHER_ADDR_LEN) == 0 ? "broadcast" : "unicast");

	ipv4_address = ntohl(dhcp->yiaddr);

	add_dhcp_response(server_data,"offered-ipv4-address","%u.%u.%u.%u",
		(ipv4_address >> 24) & 0xff, (ipv4_address >> 16) & 0xff,
		(ipv4_address >> 8) & 0xff, (ipv4_address) & 0xff);

	ipv4_address = ntohl(dhcp->siaddr);
	if(ipv4_address)
	{
		add_dhcp_response(server_data,"next-server-ipv4-address","%u.%u.%u.%u",
			(ipv4_address >> 24) & 0xff, (ipv4_address >> 16) & 0xff,
			(ipv4_address >> 8) & 0xff, (ipv4_address) & 0xff);
	}

	ipv4_address = ntohl(dhcp->giaddr);
	if(ipv4_address)
	{
		add_dhcp_response(server_data,"relay-agent-ipv4-address","%u.%u.%u.%u",
			(ipv4_address >> 24) & 0xff, (ipv4_address >> 16) & 0xff,
			(ipv4_address >> 8) & 0xff, (ipv4_address) & 0xff);
	}

	/* The file name, if not empty, should be NUL-terminated. We cannot
	 * assume that it will be, which is why we add another NUL termination.
	 */
	memmove(text_buffer, dhcp->file, sizeof(dhcp->file));
	text_buffer[sizeof(dhcp->file)] = '\0';

	if(text_buffer[0] != '\0')
		add_dhcp_response(server_data,"boot-file-name","\"%s\"",text_buffer);

	/* Process the BOOTP/DHCP options and print information for a
	 * selection of options.
	 */
	for(pos = 0 ; pos < vendor_options_length ; (void)NULL)
	{
		option_type = vendor_options[pos++];

		/* Skip the padding octet. */
		if(option_type == OPTION_TYPE_PAD)
			continue;

		/* Stop at the end marker, or the end of the options buffer. */
		if(option_type == OPTION_TYPE_END || pos == vendor_options_length)
			break;

		/* Stop at the end of the options buffer. */
		option_length = vendor_options[pos++];
		if(pos == vendor_options_length)
			break;

		/* Move the option data to a 32-bit word aligned buffer for
		 * safe access.
		 */
		memmove(aligned_buffer,&vendor_options[pos],option_length);
		option_data[option_length] = '\0';

		pos += option_length;

		/* Ignore this option? */
		if(ignore_option[option_type / 8] & (1 << (option_type % 8)))
			continue;

		switch(option_type)
		{
			/* DHCP message type */
			case OPTION_TYPE_DHCP_MESSAGE_TYPE:

				if(MESSAGE_TYPE_DISCOVER <= option_data[0] && option_data[0] <= MESSAGE_TYPE_INFORM)
				{
					static const char * message_types[8] =
					{
						"discover",
						"offer",
						"request",
						"decline",
						"acknowledge",
						"negative acknowledgement",
						"release",
						"inform",
					};

					add_dhcp_option(server_data,"dhcp-message-type","%u (%s)", option_data[0],
						message_types[option_data[0] - MESSAGE_TYPE_DISCOVER]);
				}
				else
				{
					add_dhcp_option(server_data,"dhcp-message-type","%u", option_data[0]);
				}

				break;

			/* Server identifier */
			case OPTION_TYPE_SERVER_IDENTIFIER:

				/* Minimum length is 4 octets. */
				if(option_length >= 4)
				{
					add_dhcp_option(server_data,"server-identifier","%u.%u.%u.%u",
						option_data[0],option_data[1],option_data[2],option_data[3]);
				}

				break;

			/* IP address lease time */
			case OPTION_TYPE_IP_ADDRESS_LEASE_TIME:

				/* Minimum length is 4 octets. */
				if(option_length >= 4)
				{
					uint32_t seconds = ntohl(*(uint32_t *)option_data);

					convert_seconds_to_readable_form(seconds,text_buffer,sizeof(text_buffer));

					add_dhcp_option(server_data,"ip-address-lease-time","%u seconds%s",seconds,text_buffer);
				}

				break;

			/* Subnet mask */
			case OPTION_TYPE_SUBNET_MASK:

				/* Minimum length is 4 octets. */
				if(option_length >= 4)
				{
					add_dhcp_option(server_data,"subnet-mask","%u.%u.%u.%u",
						option_data[0],option_data[1],option_data[2],option_data[3]);
				}

				break;

			/* Gateway */
			case OPTION_TYPE_GATEWAY:

				/* Minimum length is 4 octets, and the payload must
				 * be a multiple of 4, too.
				 */
				if(option_length >= 4 && (option_length % 4) == 0)
				{
					int i;

					for(i = 0 ; i < option_length ; i += 4)
					{
						add_dhcp_option(server_data,"gateway","%u.%u.%u.%u",
							option_data[i],option_data[i+1],option_data[i+2],option_data[i+3]);
					}
				}

				break;

			/* Domain name server */
			case OPTION_TYPE_DNS:

				/* Minimum length is 4 octets, and the payload must
				 * be a multiple of 4, too.
				 */
				if(option_length >= 4 && (option_length % 4) == 0)
				{
					int i;

					for(i = 0 ; i < option_length ; i += 4)
					{
						add_dhcp_option(server_data,"domain-name-server","%u.%u.%u.%u",
							option_data[i],option_data[i+1],option_data[i+2],option_data[i+3]);
					}
				}

				break;

			/* Domain name */
			case OPTION_TYPE_DOMAIN_NAME:

				add_dhcp_option(server_data,"domain-name","%s",option_data);
				break;

			/* Maximum DHCP message size */
			case OPTION_TYPE_MAXIMUM_DHCP_MESSAGE_SIZE:

				if(option_length >= 4)
					add_dhcp_option(server_data,"maximum-dhcp-message-size","%u",ntohs(*(uint16_t *)option_data));

				break;

			/* Renewal time value */
			case OPTION_TYPE_RENEWAL_TIME:

				if(option_length >= 4)
				{
					uint32_t seconds = ntohl(*(uint32_t *)option_data);

					convert_seconds_to_readable_form(seconds,text_buffer,sizeof(text_buffer));

					add_dhcp_option(server_data,"renewal-time","%u seconds%s",seconds,text_buffer);
				}

				break;

			/* Rebinding time value */
			case OPTION_TYPE_REBINDING_TIME:

				if(option_length >= 4)
				{
					uint32_t seconds = ntohl(*(uint32_t *)option_data);

					convert_seconds_to_readable_form(seconds,text_buffer,sizeof(text_buffer));

					add_dhcp_option(server_data,"rebinding-time","%u seconds%s",seconds,text_buffer);
				}

				break;

			/* Static route */
			case OPTION_TYPE_STATIC_ROUTE:

				if(decode_static_route(option_data, option_length, text_buffer, sizeof(text_buffer)) > 0)
					add_dhcp_option(server_data,"static-route","%s",text_buffer);

				break;

			/* Message from server */
			case OPTION_TYPE_MESSAGE:

				add_dhcp_option(server_data,"message","%s",option_data);
				break;

			/* Domain search (RFC 3397) */
			case OPTION_TYPE_DOMAIN_SEARCH:

				/* The data used by this option can be spread across
				 * several options. We aggregate them and then decode
				 * them all in one step. This is why we process this
				 * option only once.
				 */
				ignore_option[option_type / 8] |= (1 << (option_type % 8));

				if(decode_domain_search(vendor_options,vendor_options_length,option_type,text_buffer, sizeof(text_buffer)))
					add_dhcp_option(server_data,"domain-search","%s",text_buffer);

				break;

			/* Classless static routes (RFC 3442) */
			case OPTION_TYPE_CLASSLESS_STATIC_ROUTE:

				if(decode_classless_static_route(option_data, option_length, text_buffer, sizeof(text_buffer)) > 0)
					add_dhcp_option(server_data,"classless-static-route","%s",text_buffer);

				break;

			/* Web proxy auto-discovery protocol (RFC draft). */
			case OPTION_TYPE_PROXY_AUTODISCOVERY:

				add_dhcp_option(server_data,"web-proxy-auto-discovery","%s",option_data);
				break;

			/* LDAP URL (RFC draft). */
			case OPTION_TYPE_LDAP_URL:

				add_dhcp_option(server_data,"ldap-url","%s",option_data);
				break;

			/* NetBIOS over TCP/IP name servers */
			case OPTION_TYPE_NETBIOS_OVER_TCP_IP_NAME_SERVER:

				/* Minimum length is 4 octets, and the payload must
				 * be a multiple of 4, too.
				 */
				if(option_length >= 4 && (option_length % 4) == 0)
				{
					int i;

					for(i = 0 ; i < option_length ; i += 4)
					{
						add_dhcp_option(server_data,"netbios-over-tcp-ip-name-server","%u.%u.%u.%u",
							option_data[i],option_data[i+1],option_data[i+2],option_data[i+3]);
					}
				}

				break;

			/* NetBIOS over TCP/IP node type */
			case OPTION_TYPE_NETBIOS_OVER_TCP_IP_NODE_TYPE:

				add_dhcp_option(server_data,"netbios-over-tcp-ip-node-type","%u",option_data[0]);
				break;

			/* NetBIOS over TCP/IP scope */
			case OPTION_TYPE_NETBIOS_OVER_TCP_IP_SCOPE:

				add_dhcp_option(server_data,"netbios-over-tcp-ip-scope","%s",option_data);
				break;

			/* Perform router discovery */
			case OPTION_TYPE_PERFORM_ROUTER_DISCOVERY:

				add_dhcp_option(server_data,"perform-router-discovery","%s",option_data[0] ? "yes" : "no");
				break;

			/* Interface MTU */
			case OPTION_TYPE_INTERFACE_MTU:

				add_dhcp_option(server_data,"interface-mtu","%u",ntohs(*(uint16_t *)option_data));
				break;

			/* Network time protocol server */
			case OPTION_TYPE_NTP_SERVERS:

				/* Minimum length is 4 octets, and the payload must
				 * be a multiple of 4, too.
				 */
				if(option_length >= 4 && (option_length % 4) == 0)
				{
					int i;

					for(i = 0 ; i < option_length ; i += 4)
					{
						add_dhcp_option(server_data,"network-time-protocol-server","%u.%u.%u.%u",
							option_data[i],option_data[i+1],option_data[i+2],option_data[i+3]);
					}
				}

				break;

			/* Broadcast address */
			case OPTION_TYPE_BROADCAST_ADDRESS:

				/* Minimum length is 4 octets. */
				if(option_length >= 4)
				{
					add_dhcp_option(server_data,"broadcast-address","%u.%u.%u.%u",
						option_data[0],option_data[1],option_data[2],option_data[3]);
				}

				break;

			/* Auto-configure (RFC 2563) */
			case OPTION_TYPE_AUTO_CONFIGURE:

				add_dhcp_option(server_data,"auto-configure","%s",
					option_data[0] ? "AutoConfigure" : "DoNotAutoConfigure");

				break;

			default:

				snprintf(text_buffer,sizeof(text_buffer),"option-%u",option_type);

				add_dhcp_option(server_data,text_buffer,"%u data bytes",option_length);
				break;
		}
	}

	/* Only read a limited number of DHCP server responses? */
	if(opt_max_response_count > 0)
	{
		/* Stop looking for more DHCP server responses? */
		opt_max_response_count--;
		if(opt_max_response_count == 0)
			pcap_breakloop(pcap_handle);
	}
}

/****************************************************************************/

/*
 * UDP packet handler
 */
static void
udp_input(const struct ether_header *eframe,struct ip * ip_packet,const struct udphdr * udp_packet,uint32_t transaction_id)
{
	int checksum;

	/* Verify the UDP datagram checksum? */
	if(udp_packet->uh_sum != 0)
	{
		struct ip ip_copy;
		struct udp_pseudo_header * udp_pseudo_header;

		/* We will clobber the IP header for the calculation,
		 * so let's save it first.
		 */
		ip_copy = (*ip_packet);

		udp_pseudo_header = (struct udp_pseudo_header *)ip_packet;
		udp_pseudo_header->ih_zero1[0] = udp_pseudo_header->ih_zero1[1] = 0;
		udp_pseudo_header->ih_zero2 = 0;
		udp_pseudo_header->ih_len = udp_pseudo_header->uh_ulen;
	
		checksum = in_cksum(ip_packet,sizeof(*ip_packet) + ntohs(udp_pseudo_header->uh_ulen));
	
		/* Restore the damage. */
		(*ip_packet) = ip_copy;
	}
	/* No checksum was given. */
	else
	{
		checksum = 0;
	}
	
	/* Check if there is a response from DHCP server. */
	if ((opt_ignore_checksums || checksum == 0) && ntohs(udp_packet->uh_sport) == dhcp_server_port)
	{
		int length;

		length = ntohs(udp_packet->uh_ulen) - sizeof(struct udphdr);

		dhcp_input(eframe,ip_packet,udp_packet,(bootp_t *)((char *)udp_packet + sizeof(struct udphdr)),transaction_id,length);
	}
}

/****************************************************************************/

/*
 * IP Packet handler
 */
static void
ip_input(const struct ether_header *eframe,struct ip * ip_packet,uint32_t transaction_id)
{
	/* Verify the IP header checksum. */
	int checksum = in_cksum(ip_packet,sizeof(*ip_packet));
	
	/* Care only about UDP - since DHCP sits over UDP */
	if ((opt_ignore_checksums || checksum == 0) && ip_packet->ip_p == IPPROTO_UDP)
		udp_input(eframe,ip_packet,(struct udphdr *)((char *)ip_packet + sizeof(struct ip)),transaction_id);
}

/****************************************************************************/

/*
 * Ethernet packet handler
 */
static void
ether_input(u_char *args __attribute__((unused)), const struct pcap_pkthdr *header __attribute__((unused)), const u_char *frame)
{
	const struct ether_header *eframe = (struct ether_header *)frame;

	/* This must be an Ethernet frame (not ARP), and the destination address must
	 * either refer to the network interface we listen to or it must be
	 * the broadcast group address.
	 */
	if (htons(eframe->ether_type) == ETHERTYPE_IP && (memcmp(eframe->ether_dhost,client_mac_address,ETHER_ADDR_LEN) == 0 ||
													  memcmp(eframe->ether_dhost,broadcast_mac_address,ETHER_ADDR_LEN) == 0))
	{
		ip_input(eframe,(struct ip *)(frame + sizeof(struct ether_header)),transaction_id);
	}
}

/****************************************************************************/

/*
 * Ethernet output handler - Fills appropriate bytes in ethernet header
 */
static int
ether_output(pcap_t *pcap_handle,const u_char *frame, const uint8_t *client_mac_address, int len)
{
	struct ether_header *eframe = (struct ether_header *)frame;
	int result;

	len += sizeof(struct ether_header);

	memmove(eframe->ether_shost, client_mac_address, ETHER_ADDR_LEN);
	memmove(eframe->ether_dhost, broadcast_mac_address, ETHER_ADDR_LEN);

	eframe->ether_type = htons(ETHERTYPE_IP);

	/* Send the packet on wire */
	result = pcap_inject(pcap_handle, frame, len);

	return(result);
}

/****************************************************************************/

/*
 * IP Output handler - Fills appropriate bytes in IP header
 */
static int
ip_output(struct ip *ip_header, ip4_t src_address, ip4_t dst_address, int len)
{
	len += sizeof(struct ip);

	ip_header->ip_hl = 5;
	ip_header->ip_v = IPVERSION;
	ip_header->ip_tos = 0x10; /* minimize delay (RFC 1349) */
	ip_header->ip_len = htons(len);
	ip_header->ip_id = htons(0xffff);
	ip_header->ip_off = 0;
	ip_header->ip_ttl = 16;
	ip_header->ip_p = IPPROTO_UDP;
	ip_header->ip_sum = 0;
	ip_header->ip_src.s_addr = src_address;
	ip_header->ip_dst.s_addr = dst_address;

	ip_header->ip_sum = in_cksum(ip_header, sizeof(struct ip));

	return(len);
}

/****************************************************************************/

/*
 * UDP output - Fills appropriate bytes in UDP header
 */
static int
udp_output(struct ip *ip_header, ip4_t src_address, ip4_t dst_address, struct udphdr *udp_header, int len)
{
	struct udp_pseudo_header * udp_pseudo_header;
	
	/* Length must be even. */
	if ((len % 2) != 0)
		len++;

	len += sizeof(struct udphdr);

	udp_header->uh_sport = htons(dhcp_client_port);
	udp_header->uh_dport = htons(dhcp_server_port);
	udp_header->uh_ulen = htons(len);
	udp_header->uh_sum = 0;

	/* We fill the IP/UDP pseudo-header with defaults with regard
	 * to protocol, source IPv4 address and destination IPv4 address.
	 */
	udp_pseudo_header = (struct udp_pseudo_header *)ip_header;
	udp_pseudo_header->ih_zero1[0] = udp_pseudo_header->ih_zero1[1] = 0;
	udp_pseudo_header->ih_zero2 = 0;
	udp_pseudo_header->ih_pr = IPPROTO_UDP;
	udp_pseudo_header->ih_src = src_address;
	udp_pseudo_header->ih_dst = dst_address;
	udp_pseudo_header->ih_len = udp_pseudo_header->uh_ulen;
	
	udp_header->uh_sum = in_cksum(ip_header,sizeof(*ip_header) + ntohs(udp_pseudo_header->uh_ulen));
	
	return(len);
}

/****************************************************************************/

/*
 * DHCP output - Just fills DHCP "discover" message
 */
static int
dhcp_output(bootp_t *dhcp, const uint8_t *client_mac_address, uint32_t transaction_id, bool use_broadcast, int len)
{
	memset(dhcp, 0, sizeof(*dhcp));

	dhcp->opcode = BOOTREQUEST;
	dhcp->htype = BOOTP_HARDWARE_TYPE_10_ETHERNET;

	/* Request that the server responds by broadcast rather
	 * than unicast (RFC1531, section 2).
	 */
	if(use_broadcast)
		dhcp->flags = htons(0x8000);

	dhcp->hlen = ETHER_ADDR_LEN;
	memmove(dhcp->chaddr, client_mac_address, ETHER_ADDR_LEN);

	dhcp->xid = htonl(transaction_id);

	dhcp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

	len += sizeof(*dhcp);

	return(len);
}

/****************************************************************************/

/*
 * Adds DHCP option to the bytestream
 */
static int
fill_dhcp_option(uint8_t *option_buffer, uint8_t option_code, const void *option_data, int len)
{
	assert( 0 <= len && len < 256 );

	option_buffer[0] = option_code;
	option_buffer[1] = len;

	if(len > 0)
	{
		assert( option_data != NULL );

		memmove(&option_buffer[2], option_data, len);
	}

	len += sizeof(uint8_t) * 2;

	return(len);
}

/****************************************************************************/

/*
 * Fill DHCP options
 */
static int
fill_dhcp_discover_options(bootp_t *dhcp, int interface_mtu)
{
	static const uint8_t parameter_req_list[] =
	{
		OPTION_TYPE_SUBNET_MASK,
		OPTION_TYPE_GATEWAY,
		OPTION_TYPE_DNS,
		OPTION_TYPE_DOMAIN_NAME,
		OPTION_TYPE_INTERFACE_MTU,
		OPTION_TYPE_BROADCAST_ADDRESS,
		OPTION_TYPE_PERFORM_ROUTER_DISCOVERY,
		OPTION_TYPE_STATIC_ROUTE,
		OPTION_TYPE_NTP_SERVERS,
		OPTION_TYPE_NETBIOS_OVER_TCP_IP_NAME_SERVER,
		OPTION_TYPE_NETBIOS_OVER_TCP_IP_NODE_TYPE,
		OPTION_TYPE_NETBIOS_OVER_TCP_IP_SCOPE,
		OPTION_TYPE_IP_ADDRESS_LEASE_TIME,
		OPTION_TYPE_DHCP_MESSAGE_TYPE,
		OPTION_TYPE_SERVER_IDENTIFIER,
		OPTION_TYPE_PARAMETER_REQUEST_LIST,
		OPTION_TYPE_MESSAGE,
		OPTION_TYPE_MAXIMUM_DHCP_MESSAGE_SIZE,
		OPTION_TYPE_RENEWAL_TIME,
		OPTION_TYPE_REBINDING_TIME,
		OPTION_TYPE_LDAP_URL,
		OPTION_TYPE_AUTO_CONFIGURE,
		OPTION_TYPE_DOMAIN_SEARCH,
		OPTION_TYPE_CLASSLESS_STATIC_ROUTE,
		OPTION_TYPE_PROXY_AUTODISCOVERY
	};

	uint8_t message_type;
	uint16_t message_size;
	int len = 0;

	message_type = MESSAGE_TYPE_DISCOVER;
	len += fill_dhcp_option(&dhcp->vend[len], OPTION_TYPE_DHCP_MESSAGE_TYPE, &message_type, sizeof(message_type));

	assert( 0 < interface_mtu && interface_mtu < 65536 );

	message_size = htons(interface_mtu);
	len += fill_dhcp_option(&dhcp->vend[len], OPTION_TYPE_MAXIMUM_DHCP_MESSAGE_SIZE, &message_size, sizeof(message_size));

	len += fill_dhcp_option(&dhcp->vend[len], OPTION_TYPE_PARAMETER_REQUEST_LIST, parameter_req_list, sizeof(parameter_req_list));

	len += fill_dhcp_option(&dhcp->vend[len], OPTION_TYPE_END, NULL, 0);

	/* Make sure that the size of the option data is an even number. */
	if((len % 2) != 0)
		dhcp->vend[len++] = OPTION_TYPE_PAD;

	return(len);
}

/****************************************************************************/

/*
 * Send DHCP DISCOVER message
 */
static int
dhcp_discover(pcap_t *pcap_handle, const uint8_t *client_mac_address, int interface_mtu, uint32_t transaction_id, bool use_broadcast)
{
	int len;
	char packet[512];
	struct udphdr *udp_header;
	struct ip *ip_header;
	bootp_t *dhcp;
	ip4_t src_address = 0;
	ip4_t dst_address = 0xFFFFFFFF; /* broadcast */
	int result;

	memset(packet,0,sizeof(packet));

	ip_header = (struct ip *)(packet + sizeof(struct ether_header));
	udp_header = (struct udphdr *)(((char *)ip_header) + sizeof(struct ip));
	dhcp = (bootp_t *)(((char *)udp_header) + sizeof(struct udphdr));

	len = fill_dhcp_discover_options(dhcp, interface_mtu);

	len = dhcp_output(dhcp, client_mac_address, transaction_id, use_broadcast, len);

	/* The DHCP message must be at least 300 octets in size (RFC 1532, section 2.1).
	 * The RFC documentation states that DHCP/BOOTP relay servers may drop
	 * DHCP messages shorter than 300 octets. In practice DHCP servers (not
	 * just relay servers, mind you) may ignore DHCP messages shorter than 300
	 * octets altogether.
	 */
	if(sizeof(*ip_header) + sizeof(*udp_header) + len < 300)
		len = 300 - (sizeof(*ip_header) + sizeof(*udp_header));

	len = udp_output(ip_header, src_address, dst_address, udp_header, len);
	len = ip_output(ip_header, src_address, dst_address, len);

	assert( len <= (int)sizeof(packet) );
	assert( len >= 300 );

	result = ether_output(pcap_handle,(u_char *)packet, client_mac_address, len);

	return result;
}

/****************************************************************************/

/* This stops the packet capture operation when the timer elapses. */
static void
alarm_signal_handler(int unused_signal __attribute__((unused)))
{
	longjmp(alarm_jmp_buf, 1);
}

/****************************************************************************/

static void
print_usage(void)
{
	printf("Usage: %s "
		"[--audible] "
		"[--broadcast] "
		"[--max-responses=<number>] "
		"[--min-responses=<number>] "
		"[--timeout=<seconds>] "
		"[--help] "
		"[--ignore-checksums] "
		"[--quiet] "
		"[--verbose] "
		"[interface]\n",
		command_name);
}

/****************************************************************************/

int
main(int argc, char *argv[])
{
	static const struct option longopts[] =
	{
		{ "audible",			no_argument,		NULL,	'a'	},
		{ "broadcast",			no_argument,		NULL,	'b'	},
		{ "max-responses",		required_argument,	NULL,	'c'	},
		{ "help",				no_argument,		NULL,	'h'	},
		{ "ignore-checksums",	no_argument,		NULL,	'i'	},
		{ "min-responses",		required_argument,	NULL,	'm'	},
		{ "quiet",				no_argument,		NULL,	'q'	},
		{ "timeout",			required_argument,	NULL,	't'	},
		{ "verbose",			no_argument,		NULL,	'v'	},
		{ NULL,					0,					NULL,	0	}
	};

	struct servent * service_entry;
	char filter_command[256];
	int result = EXIT_FAILURE;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter_program;
	time_t now = time(NULL);
	int interface_mtu = 0;
	const char * s;
	char * p;
	long n;
	int c;

	/* Figure out the name of this command. Strip any
	 * leading path from it.
	 */
	command_name = argv[0];

	s = strrchr(command_name, '/');
	if(s != NULL)
		command_name = s+1;

	memset(&filter_program,0,sizeof(filter_program));

	new_list(&dhcp_server_response_list);

	/* Look at the command line parameters, if any. */
	while((c = getopt_long(argc,argv,"ac:him:qt:v",longopts,NULL)) != -1)
	{
		switch(c)
		{
			/* Send a ^G to the terminal for each DHCP response received. */
			case 'a':

				opt_audible = true;
				break;

			/* Request that the DHCP server responds by sending a broadcast message. */
			case 'b':

				opt_broadcast = true;
				break;

			/* Maximum number of DHCP server responses to process. */
			case 'c':

				/* Convert text into number; balk if the conversion
				 * failed or the resulting value is out of range.
				 */
				n = strtol(optarg,&p,0);

				if((n == 0 && p == optarg) || n < 1 || n > INT_MAX)
				{
					fprintf(stderr,"%s: Parameter '--max-responses=%s' is not valid.\n",command_name,optarg);
					goto out;
				}

				opt_max_response_count = (int)n;
				break;

			/* Print the usage information. */
			case 'h':

				print_usage();
				exit(EXIT_SUCCESS);

				break;

			/* Ignore IP and UDP checksums. */
			case 'i':
				
				opt_ignore_checksums = true;
				break;
				
			/* Minimum number of DHCP server responses required. */
			case 'm':

				/* Convert text into number; balk if the conversion
				 * failed or the resulting value is out of range.
				 */
				n = strtol(optarg,&p,0);

				if((n == 0 && p == optarg) || n < 1 || n > INT_MAX)
				{
					fprintf(stderr,"%s: Parameter '--min-responses=%s' is not valid.\n",command_name,optarg);
					goto out;
				}

				opt_min_response_count = (int)n;
				break;

			/* How long to wait for DHCP server responses to trickle in. */
			case 't':

				/* Convert text into number; balk if the conversion
				 * failed or the resulting value is out of range.
				 */
				n = strtol(optarg,&p,0);

				if((n == 0 && p == optarg) || n < 0 || n > INT_MAX)
				{
					fprintf(stderr,"%s: Parameter '--timeout=%s' is not valid.\n",command_name,optarg);
					goto out;
				}

				opt_timeout = (int)n;
				break;

			/* Minimize output. */
			case 'q':

				opt_quiet = true;
				opt_verbose = false;

				break;

			/* Print additional processing information. */
			case 'v':

				opt_verbose = true;
				opt_quiet = false;

				break;

			default:

				fprintf(stderr,"%s: %s - %s\n",command_name,optarg,"option not known");
				goto out;
		}
	}

	argc -= optind;
	argv += optind;

	/* No interface name provided? Pick the one which the PCAP
	 * API suggests.
	 */
	if(argc == 0)
	{
		interface_name = pcap_lookupdev(errbuf);
		if(interface_name == NULL)
		{
			if(!opt_quiet)
				fprintf(stderr,"%s: Unable to pick network interface: %s.\n",command_name,errbuf);

			goto out;
		}
	}
	else
	{
		interface_name = argv[0];
	}

	/* Show the preset options, or in the case of the network interface,
	 * whatever the PCAP API may have picked.
	 */
	if(opt_verbose)
	{
		printf("%s: Using network interface %s.\n",command_name,interface_name);
		printf("%s: Will wait for up to %d seconds for DHCP responses to arrive.\n",command_name,opt_timeout);
	}

	/* Get the MAC address and MTU of the interface */
	if (get_mac_address_and_mtu(interface_name, client_mac_address, &interface_mtu) != 0)
	{
		if(!opt_quiet)
			fprintf(stderr,"%s: Unable to get MAC address and MTU for %s.\n",command_name,interface_name);

		goto out;
	}

	/* Open the device and get PCAP handle for it. We request snapshots large
	 * enough to fill the MTU plus 14 bytes for the MAC header, promiscuous mode is
	 * disabled (not needed), and we wait up to 10 milliseconds for multiple frames
	 * to arrive (we don't want to read just one single frame at a time).
	 */
	pcap_handle = pcap_open_live(interface_name, 14+interface_mtu, false, 10, errbuf);
	if (pcap_handle == NULL)
	{
		if(!opt_quiet)
			fprintf(stderr,"%s: Unable to open device %s: %s.\n",command_name,interface_name,errbuf);

		goto out;
	}

	/* Figure out the port numbers to use for sending and receiving DHCP messages. */
	service_entry = getservbyname("bootps", "udp");
	if(service_entry != NULL)
	{
		dhcp_server_port = ntohs(service_entry->s_port);
	}
	else
	{
		dhcp_server_port = DEFAULT_BOOTP_SERVER_PORT;

		if(!opt_quiet)
			fprintf(stderr,"%s: Using default DHCP server port number %d.\n",command_name,dhcp_server_port);
	}

	service_entry = getservbyname("bootpc", "udp");
	if(service_entry != NULL)
	{
		dhcp_client_port = ntohs(service_entry->s_port);
	}
	else
	{
		dhcp_client_port = DEFAULT_BOOTP_CLIENT_PORT;

		if(!opt_quiet)
			fprintf(stderr,"%s: Using default DHCP client port number %d.\n",command_name,dhcp_client_port);
	}

	/* We are only interested in the DHCP server responses, which is why
	 * we enable a BPF filter program here. This way we only get to see
	 * suitable frames instead of everything else, too.
	 */
	snprintf(filter_command, sizeof(filter_command), "udp port %d", dhcp_server_port);

	if(pcap_compile(pcap_handle,&filter_program,filter_command,1,0) < 0 || pcap_setfilter(pcap_handle,&filter_program) < 0)
	{
		if(!opt_quiet)
			fprintf(stderr,"%s: Unable to set up packet filter for device %s.\n",command_name,interface_name);

		goto out;
	}

	/* We need a transaction ID to match our DHCP DISCOVER message
	 * against the DHCP server response.
	 *
	 * The DHCP transaction number should be reasonably unique.
	 * We use a pseudo-random number, which is why we need to
	 * prime the generator with a seed value.
	 */
	srand((unsigned)now + getpid() + argc);

	transaction_id = (uint32_t)rand();

	/* Send DHCP DISCOVER message */
	if (dhcp_discover(pcap_handle,client_mac_address,interface_mtu,transaction_id,opt_broadcast) < 0)
	{
		if(!opt_quiet)
			fprintf(stderr,"%s: Unable to send DHCP DISCOVER on device %s: %s.\n",command_name,interface_name,pcap_geterr(pcap_handle));

		goto out;
	}

	/* Wait a limited time for all DHCP server responses to trickle in?
	 * Once this timeout has elapsed no further responses will be
	 * recorded and this command will exit.
	 */
	if(opt_timeout > 0)
	{
		if(setjmp(alarm_jmp_buf) == 0)
		{
			signal(SIGALRM, alarm_signal_handler);

			alarm((unsigned)opt_timeout);

			/* Listen till the DHCP OFFERs come. */
			pcap_loop(pcap_handle, -1, ether_input, NULL);
		}
	}
	else
	{
		/* Listen till the DHCP OFFERs come. */
		pcap_loop(pcap_handle, -1, ether_input, NULL);
	}

	/* Show what was received. */
	if(!opt_quiet)
		print_dhcp_server_data();

	/* Should we check if more than one DHCP server responded? */
	if(opt_min_response_count > 0)
	{
		int num_responses_received = 0;
		const struct Node * node;

		for(node = get_list_head(&dhcp_server_response_list) ; node != NULL ; node = get_next_node(node))
			num_responses_received++;

		/* Fewer reponses received than required? */
		if(num_responses_received < opt_min_response_count)
			goto out;
	}

	result = EXIT_SUCCESS;

 out:

	if(pcap_handle != NULL)
	{
		pcap_freecode(&filter_program);

		pcap_close(pcap_handle);
	}

	return(result);
}
