#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <poll.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include <linux/if_packet.h>
#include <linux/igmp.h>
#include <linux/mroute.h>

#define LOG_TRACE
#define LOG_ERROR

#ifdef LOG_TRACE
#define _trace(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
		fprintf(stderr, "[TRACE] (%d): " fmt "\n", __LINE__, ##__VA_ARGS__);                                                                         \
	} while (0)
#else
#define _trace(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
	} while (0)
#endif

#ifdef LOG_ERROR
#define _error(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
		fprintf(stderr,                                                                                                                              \
				"%s[ERROR] (%d): " fmt "%s\n",                                                                                                       \
				isatty(STDERR_FILENO) ? "\x1B[31m" : "",                                                                                             \
				__LINE__,                                                                                                                            \
				##__VA_ARGS__,                                                                                                                       \
				isatty(STDERR_FILENO) ? "\x1B[0m" : "");                                                                                             \
	} while (0)
#else
#define _error(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
	} while (0)
#endif

#define SIZEOF_ARRAY(x) (sizeof(x) / sizeof(x[0]))

#define MLD_REQUEST_SOURCE_ADDRESS "2003:1b0b:fffd:ffff:0:c613:8c01:0"
#define MLD_REQUEST_GROUP_ADDRESS_PREFIX "ff38::"

static int iptv_igmp_receive_socket_init(void);
static int iptv_multicast_send_socket_init(void);
static int wan_mld_send_socket_init(void);
static int wan_multicast_receive_socket_init(void);
static void iptv_igmp_receive(void);
static void wan_multicast_receive(void);
static void exit_cb(int signal);

static const char *iptv_ifname = NULL;
static uint32_t iptv_ifindex = 0;
static const char *wan_ifname = NULL;
static uint32_t wan_ifindex = 0;
static struct sockaddr_in6 mld_request_source = {0};
static int iptv_igmp_receive_socket = -1;
static int iptv_multicast_send_socket = -1;
static int wan_mld_send_socket = -1;
static int wan_multicast_receive_socket = -1;

int main(int argc, char **argv)
{
	static const char usage[] = "Usage: %s -i <iptv_ifname> -w <wan_ifname>\n";

	int error = 0;
	struct pollfd poll_fd[2];

	int opt;
	while ((opt = getopt(argc, argv, "i:w:")) != -1) {
		switch (opt) {
			case 'i':
				iptv_ifname = optarg;
				break;
			case 'w':
				wan_ifname = optarg;
				break;
			default:
				printf(usage, argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (iptv_ifname == NULL || wan_ifname == NULL) {
		printf(usage, argv[0]);
		return EXIT_FAILURE;
	}

	error = iptv_ifindex = if_nametoindex(iptv_ifname);
	if (error == 0) {
		_error("if_nametoindex error: %s", strerror(errno));
		printf(usage, argv[0]);
		return EXIT_FAILURE;
	}

	error = wan_ifindex = if_nametoindex(wan_ifname);
	if (error == 0) {
		_error("if_nametoindex error: %s", strerror(errno));
		printf(usage, argv[0]);
		return EXIT_FAILURE;
	}

	// TODO: load mld request source adddress from config or command-line option
	mld_request_source.sin6_family = AF_INET6;
	error = inet_pton(AF_INET6, MLD_REQUEST_SOURCE_ADDRESS, &(mld_request_source.sin6_addr));
	if (error != 1) {
		_error("inet_pton error: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	// mld_request_source.sin6_port = 0;

	error = iptv_igmp_receive_socket_init();
	if (error < 0) {
		exit_cb(SIGABRT);
	}

	error = iptv_multicast_send_socket_init();
	if (error < 0) {
		exit_cb(SIGABRT);
	}

	error = wan_mld_send_socket_init();
	if (error < 0) {
		exit_cb(SIGABRT);
	}

	error = wan_multicast_receive_socket_init();
	if (error < 0) {
		exit_cb(SIGABRT);
	}

	poll_fd[0].fd = iptv_igmp_receive_socket;
	poll_fd[0].events = POLLIN;

	poll_fd[1].fd = wan_multicast_receive_socket;
	poll_fd[1].events = POLLIN;

	signal(SIGINT, exit_cb);
	signal(SIGTERM, exit_cb);

	while (1) {
		error = poll(poll_fd, SIZEOF_ARRAY(poll_fd), 1000);
		if (error < 0) {
			_error("poll error: %s", strerror(errno));
			exit_cb(SIGABRT); // TODO:
		}

		if (poll_fd[0].revents & POLLIN) {
			iptv_igmp_receive();
		}

		if (poll_fd[1].revents & POLLIN) {
			wan_multicast_receive();
		}
	}

	return 0;
}

static void exit_cb(int signal)
{
	if (iptv_igmp_receive_socket > 0) {
		close(iptv_igmp_receive_socket);
	}

	if (iptv_multicast_send_socket > 0) {
		close(iptv_multicast_send_socket);
	}

	if (wan_mld_send_socket > 0) {
		close(wan_mld_send_socket);
	}

	if (wan_multicast_receive_socket > 0) {
		close(wan_multicast_receive_socket);
	}

	fprintf(stderr, "\n");
	_trace("done");

	exit(0);
}

static int iptv_igmp_receive_socket_init(void)
{
	int error = 0;

	// NOTE:
	// - we use AF_PACKET + ETH_P_ALL to intercept all IGMP packets
	// - another option to get all IGMP packets would be to open a control socket for kernel multicast routing table
	// - but since there can be only one socket on the system on which the call MRT_INIT succeeds that soultion is not feasible

#if 1
	error = iptv_igmp_receive_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (error < 0) {
		_error("socket error: %s", strerror(errno));
		return -1;
	}

	struct sockaddr_ll bind_address = {0};
	bind_address.sll_family = AF_PACKET;
	bind_address.sll_protocol = htons(ETH_P_ALL);
	bind_address.sll_ifindex = (int) iptv_ifindex;

	error = bind(iptv_igmp_receive_socket, (struct sockaddr *) &bind_address, sizeof(bind_address));
	if (error < 0) {
		_error("bind error: %s", strerror(errno));
		return -1;
	}
#else
	error = iptv_igmp_receive_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	if (error < 0) {
		_error("socket error: %s", strerror(errno));
		exit_cb(SIGABRT);
	}

	error = setsockopt(iptv_igmp_receive_socket, IPPROTO_IP, MRT_INIT, &(int){1}, sizeof(int));
	if (error < 0) {
		_error("setsockopt error: %s", strerror(errno));
		exit_cb(SIGABRT);
	}

	// TODO:
	//  - MRT_ADD_VIF
	//  - MRT_DONE on exit
#endif

	return 0;
}

static int iptv_multicast_send_socket_init(void)
{
	int error = 0;

	// NOTE:
	// - we use this socket for sending out multicast packets recevied on wan
	// - since the received ipv6 packet has an encapsulated ipv4 packet we have two options:
	// a) create a raw socket and forward bytes from the start of ipv4 header
	// b) create a UDP multicast socket and send a multicast packet using udp payload from received ipv4 in ipv6 packet

#if 1
	error = iptv_multicast_send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // IPPROTO_RAW implies enabled IP_HDRINCL
	if (error < 0) {
		_error("socket error: %s", strerror(errno));
		return -1;
	}

	struct ifreq ifr = {{0}};
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iptv_ifname);

	error = setsockopt(iptv_multicast_send_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr));
	if (error < 0) {
		_error("setsockopt error: %s", strerror(errno));
		return -1;
	}
#else
	error = iptv_multicast_send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (error < 0) {
		_error("socket error: %s", strerror(errno));
		return -1;
	}

	error =
		setsockopt(iptv_multicast_send_socket, IPPROTO_IP, IP_MULTICAST_IF, &(struct ip_mreqn){.imr_ifindex = iptv_ifindex}, sizeof(struct ip_mreqn));
	if (error < 0) {
		_error("setsockopt error: %s", strerror(errno));
		return -1;
	}

	// TODO: setsockopt IP_MULTICAST_LOOP off
#endif

	return 0;
}

static int wan_mld_send_socket_init(void)
{
	int error = 0;

	// NOTE:
	// - we use wan_mld_send_socket just for sending mld requests since MCAST_JOIN_SOURCE_GROUP is not supported on AF_PACKET
	// - and we use AF_PACKET for receiving because kernel is not sending multicast packets to the socket if we use IPPROTO_IPIP a protocol

	error = wan_mld_send_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (error < 0) {
		_error("socket error: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int wan_multicast_receive_socket_init(void)
{
	int error = 0;

#if 1
	error = wan_multicast_receive_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
	if (error < 0) {
		_error("socket error: %s", strerror(errno));
		return -1;
	}

	struct sockaddr_ll bind_address = {0};
	bind_address.sll_family = AF_PACKET;
	bind_address.sll_protocol = htons(ETH_P_IPV6);
	bind_address.sll_ifindex = (int) wan_ifindex;

	error = bind(wan_multicast_receive_socket, (struct sockaddr *) &bind_address, sizeof(bind_address));
	if (error < 0) {
		_error("bind error: %s", strerror(errno));
		return -1;
	}
#else
	// NOTE:
	// - not working as expected...
	// - nothing is received on socket after MCAST_JOIN_SOURCE_GROUP is set although multicast packets are received (seen with tcpdump)

	error = wan_multicast_receive_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_IPIP);
	if (error < 0) {
		_error("socket error: %s", strerror(errno));
		return -1;
	}

#if 0
	struct ifreq ifr = {{0}};
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", wan_ifname);
	error = setsockopt(wan_multicast_receive_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr));
	if (error < 0) {
		_error("setsockopt error: %s", strerror(errno));
		return -1;
	}
#endif

	struct sockaddr_in6 bind_address = {0};
	bind_address.sin6_family = AF_INET6;
	bind_address.sin6_addr = in6addr_any;
	bind_address.sin6_port = htons(10000);

	error = bind(wan_multicast_receive_socket, (struct sockaddr *) &bind_address, sizeof(bind_address));
	if (error < 0) {
		_error("bind error: %s", strerror(errno));
		return -1;
	}
#endif

	return 0;
}

static void iptv_igmp_receive(void)
{
	static unsigned char datagram[1024 * 8] = {0};

	ssize_t datagram_size = recv(iptv_igmp_receive_socket, datagram, sizeof datagram, 0);
	const unsigned char *datagram_end = datagram + datagram_size;

	if (datagram_size < 0) {
		_error("recv error: %s", strerror(errno));
		return;
	}

	const unsigned char *ipv4_header_start = datagram;
	if (ipv4_header_start + sizeof(struct iphdr) > datagram_end) {
		_error("ipv4 header size overflows datagram size");
		return;
	}

	const unsigned char *ip_protocol_offset = ipv4_header_start + offsetof(struct iphdr, protocol);
	if (*ip_protocol_offset != IPPROTO_IGMP) {
		return;
	}

	const unsigned char *igmp_header_start = datagram + ((*ipv4_header_start & 0x0F) * 4);
	if (igmp_header_start + sizeof(struct igmphdr) > datagram_end) {
		_error("ipv4 header size overflows datagram size");
		return;
	}

	const unsigned char *igmp_type_offset = igmp_header_start + offsetof(struct igmphdr, type);
	const unsigned char *igmp_group_offset = igmp_header_start + offsetof(struct igmphdr, group);

	// TODO: spoof only pre defnied iptv group addresses?

	// join or lave action
	int mld_request_action;
	switch (*igmp_type_offset) {
		case IGMPV2_HOST_MEMBERSHIP_REPORT:
			_trace("got IGMP_V2_MEMBERSHIP_REPORT");
			mld_request_action = MCAST_JOIN_SOURCE_GROUP;
			break;
		case IGMP_HOST_LEAVE_MESSAGE:
			_trace("IGMP_HOST_LEAVE_MESSAGE");
			mld_request_action = MCAST_LEAVE_SOURCE_GROUP;
			break;
		default:
			_trace("unhandled IGMP message type: 0x%x", *igmp_type_offset);
			return;
	}

	int error = 0;

	// craft ipv6 group address based on ipv4 grouup address from IGMP request
	char group_address_ipv4_str[INET_ADDRSTRLEN] = {0};
	if (!inet_ntop(AF_INET, igmp_group_offset, group_address_ipv4_str, sizeof group_address_ipv4_str)) {
		_error("inet_ntop error: %s", strerror(errno));
		return;
	}
	_trace("ipv4 group address: %s", group_address_ipv4_str);

	char group_address_ipv6_str[INET6_ADDRSTRLEN] = {0};
	strcat(group_address_ipv6_str, MLD_REQUEST_GROUP_ADDRESS_PREFIX);
	strcat(group_address_ipv6_str, group_address_ipv4_str);
	_trace("ipv6 group address: %s", group_address_ipv6_str);

	// craft and send out an SSM MLD request on wan_mld_send_socket
	struct group_source_req mld_request = {0};
	mld_request.gsr_interface = wan_ifindex;
	memcpy(&mld_request.gsr_source, &mld_request_source, sizeof(mld_request_source));

	struct sockaddr_in6 *group_address = (struct sockaddr_in6 *) &mld_request.gsr_group;
	group_address->sin6_family = AF_INET6;
	error = inet_pton(AF_INET6, group_address_ipv6_str, &(group_address->sin6_addr));
	if (error != 1) {
		_error("inet_pton error: %s", strerror(errno));
		return;
	}
	// group_address->sin6_port = 0; // TODO: ??

	// send send SSM MLD request
	error = setsockopt(wan_mld_send_socket, IPPROTO_IPV6, mld_request_action, &mld_request, sizeof(mld_request));
	if (error < 0) {
		_error("setsockopt error: %s", strerror(errno));
		return;
	}
}

static void wan_multicast_receive(void)
{
	static unsigned char datagram[1024 * 8] = {0};

	ssize_t datagram_size = recv(wan_multicast_receive_socket, datagram, sizeof datagram, 0);
	const unsigned char *datagram_end = datagram + datagram_size;

	if (datagram_size < 0) {
		_error("recv error: %s", strerror(errno));
		return;
	}

	const unsigned char *ipv6_header_start = datagram;
	if (ipv6_header_start + sizeof(struct ip6_hdr) > datagram_end) {
		_error("ipv6 header size overflows datagram size");
		return;
	}

	const unsigned char *ipv6_next_header_offset = ipv6_header_start + offsetof(struct ip6_hdr, ip6_nxt);
	if (*ipv6_next_header_offset != IPPROTO_IPIP) {
		return;
	}

	const unsigned char *ipv6_source_address_offset = ipv6_header_start + offsetof(struct ip6_hdr, ip6_src);
	if (memcmp(ipv6_source_address_offset, &mld_request_source.sin6_addr, sizeof(struct in6_addr)) != 0) {
		return;
	}

	// const unsigned char *ipv6_destination_address_offset = ipv6_header_start + offsetof(struct ip6_hdr, ip6_dst);
	// TODO: check that ipv6_destination_address has MLD_REQUEST_GROUP_ADDRESS_PREFIX

	const unsigned char *ipv4_header_start = datagram + sizeof(struct ip6_hdr);
	if (ipv4_header_start + sizeof(struct iphdr) > datagram_end) {
		_error("ipv4 header size overflows datagram size");
		return;
	}

	uint16_t ipv4_total_length;
	const unsigned char *ipv4_total_length_offset = ipv4_header_start + offsetof(struct iphdr, tot_len);
	memcpy(&ipv4_total_length, ipv4_total_length_offset, sizeof(ipv4_total_length));

	uint32_t ipv4_destination_address;
	const uint8_t *ipv4_destination_address_offset = ipv4_header_start + offsetof(struct iphdr, daddr);
	memcpy(&ipv4_destination_address, ipv4_destination_address_offset, sizeof(ipv4_destination_address));

	// NOTE:
	// - based on sendto_address kernel will add L2 address
	struct sockaddr_in sendto_address = {0};
	sendto_address.sin_family = AF_INET;
	sendto_address.sin_addr.s_addr = ipv4_destination_address;

	ssize_t sent = sendto(iptv_multicast_send_socket,
						  ipv4_header_start,
						  ntohs(ipv4_total_length),
						  0,
						  (struct sockaddr *) &sendto_address,
						  sizeof(sendto_address));
	if (sent < 0) {
		_error("sendto() failed: %s", strerror(errno));
		return;
	}
}
