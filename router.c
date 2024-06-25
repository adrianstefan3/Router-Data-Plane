#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ICMP_SIZE sizeof(struct icmphdr)
#define IP_SIZE sizeof(struct iphdr)
#define ETH_SIZE sizeof(struct ether_header)
#define ARP_SIZE sizeof(struct arp_header)
#define ICMP_REPLY 0
#define ICMP_REQUEST 8
#define DEST_UNREACH 3
#define TTL_EXCEEDED 11

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

void send_icmp_message(char *buf, int interface, uint8_t type) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + ETH_SIZE);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + ETH_SIZE + IP_SIZE);
	size_t ip_len = 0;

	if (type != ICMP_REPLY) {
		ip_len = IP_SIZE + ICMP_SIZE + IP_SIZE + 8;
	} else {
		ip_len = IP_SIZE + ICMP_SIZE;
	}

	size_t total_len = ETH_SIZE + IP_SIZE + ICMP_SIZE;
	
	struct iphdr *date_vechi = malloc(IP_SIZE + 8);
	memcpy(date_vechi, ip_hdr, IP_SIZE + 8);

	//Rescriere Ethernet Header - adrese MAC
	uint8_t *aux_mac = malloc(6 * sizeof(uint8_t));
	memcpy(aux_mac, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux_mac, 6);

	//Rescriere IP Header
	uint32_t aux_ip = inet_addr(get_interface_ip(interface));
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux_ip;
	ip_hdr->tot_len = htons(ip_len);
	ip_hdr->ttl = 64; // resetare TTL
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, IP_SIZE));

	//Rescriere ICMP Header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	size_t icmp_len = ICMP_SIZE;
	if (type != ICMP_REPLY) {
		memcpy(buf + total_len, date_vechi, IP_SIZE + 8);
		icmp_len += IP_SIZE + 8;
	}
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, icmp_len));

	//Trimitere pachet
	if (type != ICMP_REPLY) {
		send_to_link(interface, buf, total_len + IP_SIZE + 8);
	} else {
		send_to_link(interface, buf, total_len);
	}
	
	free(aux_mac);
	free(date_vechi);
}

struct route_table_entry* longest_prefix_match(struct route_table_entry *rtable, int rtabel_len, uint32_t ip_destinatie) {
	struct route_table_entry *best_route = NULL;
	int left = 0, right = rtabel_len - 1, mid;

	while (left <= right) {
		mid = (left + right) / 2;
		if ((ip_destinatie & rtable[mid].mask) == rtable[mid].prefix) {
			if (best_route == NULL || ntohl(rtable[mid].mask) > ntohl(best_route->mask)) {
				best_route = &rtable[mid];
			}
			left = mid + 1;
		} else if (ntohl(rtable[mid].prefix) < ntohl(ip_destinatie)) {
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}

	return best_route;
}

int cmpfunc(const void *a, const void *b) {
	struct route_table_entry *ia = (struct route_table_entry *)a;
	struct route_table_entry *ib = (struct route_table_entry *)b;
	if (ia->prefix == ib->prefix) {
		return ntohl(ia->mask) - ntohl(ib->mask);
	} else {
		return ntohl(ia->prefix) - ntohl(ib->prefix);
	}
}

int search_arp_entry(struct arp_table_entry *arp_table, int arp_table_len, uint32_t ip_destinatie) {
	for (unsigned i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_destinatie) {
			return i;
		}
	}
	return -1;
}

void recv_arp_reply(char *buf, queue q, int *q_len) {
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ETH_SIZE);
	arp_table[arp_table_len].ip = arp_hdr->spa;
	memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
	arp_table_len++;

	char *packet = NULL;
	int len = *q_len;
	for (int i = 0; i < len && !queue_empty(q); i++) {
		packet = queue_deq(q);
		struct ether_header *eth_hdr = (struct ether_header *)packet;
		struct iphdr *ip_hdr = (struct iphdr *)(packet + ETH_SIZE);
		size_t packet_len = ETH_SIZE + ntohs(ip_hdr->tot_len);

		struct route_table_entry *next_entry = longest_prefix_match(rtable, rtable_len, ip_hdr->daddr);

		if (next_entry == NULL) {
			continue;
		}

		int arp_entry_id = search_arp_entry(arp_table, arp_table_len, next_entry->next_hop);

		if (arp_entry_id == -1) {
			queue_enq(q, packet);
			continue;
		}

		uint8_t *mac_aux = malloc(6 * sizeof(uint8_t));
		get_interface_mac(next_entry->interface, mac_aux);

		memcpy(eth_hdr->ether_shost, mac_aux, 6);
		memcpy(eth_hdr->ether_dhost, arp_table[arp_entry_id].mac, 6);
		free(mac_aux);
		
		send_to_link(next_entry->interface, packet, packet_len);
		*q_len = (*q_len) - 1;
	}
}

void recv_arp_request(char *buf, int interface, size_t len) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ETH_SIZE);

	uint8_t *mac_aux = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, mac_aux);

	//Rescriere ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, mac_aux, 6);

	//Rescriere ARP header
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	memcpy(arp_hdr->sha, mac_aux, 6);
	arp_hdr->op = htons(2);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);

	//Trimitere ARP reply
	send_to_link(interface, buf, len);
	free(mac_aux);
}

void send_arp_request(char *buf, int interface, uint32_t ip_target) {
	char send_buf[MAX_PACKET_LEN];
	struct ether_header *send_eth_hdr = (struct ether_header *)send_buf;
	struct arp_header *send_arp_hdr = (struct arp_header *)(send_buf + ETH_SIZE);

	uint8_t *mac_aux = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, mac_aux);
	uint8_t *mac_broadcast = malloc(6 * sizeof(uint8_t));
	memset(mac_broadcast, 0xFF, 6);

	//Setare ethernet header
	memcpy(send_eth_hdr->ether_shost, mac_aux, 6);
	memcpy(send_eth_hdr->ether_dhost, mac_broadcast, 6);
	send_eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	//Setare ARP header
	send_arp_hdr->htype = htons(1);
	send_arp_hdr->ptype = htons(ETHERTYPE_IP);
	send_arp_hdr->hlen = 6;
	send_arp_hdr->plen = 4;
	send_arp_hdr->op = htons(1);
	memcpy(send_arp_hdr->sha, mac_aux, 6);
	send_arp_hdr->spa = inet_addr(get_interface_ip(interface));
	memset(send_arp_hdr->tha, 0, 6);
	send_arp_hdr->tpa = ip_target;

	//Trimitire ARP request
	send_to_link(interface, send_buf, ETH_SIZE + ARP_SIZE);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 65000);
	DIE(rtable == NULL, "memory");
	arp_table = malloc(sizeof(struct arp_table_entry) * 10000);
	DIE(arp_table == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;

	queue q = queue_create();
	int q_len = 0;

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmpfunc);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		//Verificare IPv4 type
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + ETH_SIZE);

			//Verificare Checksum IP
			uint16_t recv_sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t new_sum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
			if (recv_sum != new_sum) {
				continue;
			}

			//Verificare destinatie == router
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + ETH_SIZE + IP_SIZE);
				if (icmp_hdr->type == ICMP_REQUEST) {
					send_icmp_message(buf, interface, ICMP_REPLY);
				}
				continue;
			}

			//Verificare TTL
			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
				send_icmp_message(buf, interface, TTL_EXCEEDED);
				continue;
			}
			ip_hdr->ttl -= 1;

			//Cautare in tabela de rutare
			struct route_table_entry *next_entry = longest_prefix_match(rtable, rtable_len, ip_hdr->daddr);

			if (next_entry == NULL) {
				send_icmp_message(buf, interface, DEST_UNREACH);
				continue;
			}

			//Actualizare checksum
			ip_hdr->check = 0;
			uint16_t new_check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
			ip_hdr->check = htons(new_check);

			//Rescriere MAC sursa si destinatie
			uint8_t *mac_sursa = malloc(6 * sizeof(uint8_t));
			get_interface_mac(next_entry->interface, mac_sursa);

			//Cautare MAC destinatie
			int arp_entry_id = search_arp_entry(arp_table, arp_table_len, next_entry->next_hop);

			if (arp_entry_id == -1) {
				void *queue_buf = malloc(len);
				memcpy(queue_buf, buf, len);
				queue_enq(q, queue_buf);
				q_len++;

				send_arp_request(buf, next_entry->interface, next_entry->next_hop);
				continue;
			}

			//Actualizare MAC destinatie si sursa
			memcpy(eth_hdr->ether_dhost, arp_table[arp_entry_id].mac, 6);
			memcpy(eth_hdr->ether_shost, mac_sursa, 6);

			//Trimitere pachet
			send_to_link(next_entry->interface, buf, len);
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + ETH_SIZE);

			if (htons(arp_hdr->op) == 2) {
				recv_arp_reply(buf, q, &q_len);
				continue;
			} else if (htons(arp_hdr->op) == 1) {
				recv_arp_request(buf, interface, len);
				continue;
			}
		}
	}
	free(rtable);
	free(arp_table);
}
