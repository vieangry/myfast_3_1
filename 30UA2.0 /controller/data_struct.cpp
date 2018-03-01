#include "data_struct.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

int encode_alert_packet(ALERT_PACKET pkt, unsigned char* msg) {
	int len = 0, i = 0;
	unsigned char* p = msg;
	memcpy(p, &pkt.timeStamp, 4);
	p += 4;
	len += 4;
	
	memcpy(p, &pkt.protocol_type, 1);
	p++;
	len++;
	
	memcpy(p, &pkt.EGP_ID, 1);
	p++;
	len++;

	memcpy(p, &pkt.port_status, 1);
	p++;
	len++;

	for(i=0; i<8; i++) {
		if(pkt.inrate_byte[i] >= 0) {
			memcpy(p, &pkt.inrate_byte[i], 2);
			p += 2;
			len += 2;

			memcpy(p, &pkt.outrate_byte[i], 2);
			p += 2;
			len += 2;

			memcpy(p, &pkt.inrate_pkt[i], 2);
			p += 2;
			len += 2;

			memcpy(p, &pkt.outrate_pkt[i], 2);
			p += 2;
			len += 2;
		}
	}

	return len;
}

void decode_alert_packet(ALERT_PACKET* pkt, unsigned char* msg) {
	unsigned char* p = msg;
	int i = 0;
	memcpy(&pkt->timeStamp, p, 4);
	p += 4;
	
	memcpy(&pkt->protocol_type, p, 1);
	p++;
	
	memcpy(&pkt->EGP_ID, p, 1);
	p++;

	memcpy(&pkt->port_status, p, 1);
	p++;

	for(i=0; i<8; i++) {
	if((pkt->port_status & (1<<i)) != 0) {
			memcpy(&pkt->inrate_byte[i], p, 2);
			p += 2;
			memcpy(&pkt->outrate_byte[i], p, 2);
			p += 2;
			memcpy(&pkt->inrate_pkt[i], p, 2);
			p += 2;
			memcpy(&pkt->outrate_pkt[i], p, 2);
			p += 2;
		} else {
			pkt->inrate_byte[i] = -1;
			pkt->outrate_byte[i] = -1;
			pkt->inrate_pkt[i] = -1;
			pkt->outrate_pkt[i] = -1;
		}
	}
}

void print_alert_packet(ALERT_PACKET pkt) {
	int i = 0;
	printf("protocol_type = %02x | EPG_ID = %d\n", pkt.protocol_type, pkt.EGP_ID);
	for(i=0; i<8; i++) {
		if((pkt.port_status & (1<<(7-i))) != 0) printf("1");
		else {
			printf("0");
		}
	}
	printf("\n");
	for(i=0; i<8; i++) {
		if((pkt.port_status & (1<<i)) != 0) {
			printf("port %d:\n", i);
			printf("inrate_byte = %d outrate_byte = %d\n", pkt.inrate_byte[i], pkt.outrate_byte[i]);
			printf("inrate_pkt = %d outrate_pkt = %d\n", pkt.inrate_pkt[i], pkt.outrate_pkt[i]);
		}
	}
}

int encode_alert_cancel_packet(ALERT_CANCEL_PACKET pkt, unsigned char* msg) {
	int len = 0;
	unsigned char* p = msg;
	memcpy(p, &pkt.timeStamp, 4);
	p += 4;
	len += 4;
	
	memcpy(p, &pkt.protocol_type, 1);
	p++;
	len++;
	
	memcpy(p, &pkt.EGP_ID, 1);
	p++;
	len++;

	return len;
}

void decode_alert_cancel_packet(ALERT_CANCEL_PACKET* pkt, unsigned char* msg) {
	unsigned char* p = msg;
	memcpy(&pkt->timeStamp, p, 4);
	p += 4;
	
	memcpy(&pkt->protocol_type, p, 1);
	p++;

	memcpy(&pkt->EGP_ID, p, 1);
	p++;
}

void print_alert_cancel_packet(ALERT_CANCEL_PACKET pkt) {
	printf("protocol_type = %02x | EGP_ID = %d\n", pkt.protocol_type, pkt.EGP_ID);
}

int encode_abnormal_packet(ABNORMAL_PACKET pkt, unsigned char* msg) {
	unsigned char* p = msg;
	int len = 0;
	memcpy(p, &pkt.timeStamp, 4);
	p += 4;
	len += 4;
	
	memcpy(p, &pkt.protocol_type, 1);
	p++;
	len++;

	memcpy(p, &pkt.EGP_ID, 1);
	p++;
	len++;

	memcpy(p, &pkt.port, 1);
	p++;
	len++;

	memcpy(p, &pkt.head_len, 2);
	p += 2;
	len += 2;
	
	memcpy(p, &pkt.datalinklayer_len, 1);
	p++;
	len++;
	
	memcpy(p, &pkt.networklayer_len, 1);
	p++;
	len++;
	
	memcpy(p, &pkt.transportlayer_len, 1);
	p++;
	len++;
	
	memcpy(p, pkt.head_data, pkt.head_len);
	p += pkt.head_len;
	len += pkt.head_len;

	return len;
}

void decode_abnormal_packet(ABNORMAL_PACKET *pkt, unsigned char* msg) {
	unsigned char* p = msg;
	memcpy(&pkt->timeStamp, p, 4);
	p += 4;
	
	memcpy(&pkt->protocol_type, p, 1);
	p++;

	memcpy(&pkt->EGP_ID, p, 1);
	p++;

	memcpy(&pkt->port, p, 1);
	p++;

	memcpy(&pkt->head_len, p, 2);
	p += 2;
	
	memcpy(&pkt->datalinklayer_len, p, 1);
	p++;
	
	memcpy(&pkt->networklayer_len, p, 1);
	p++;
	
	memcpy(&pkt->transportlayer_len, p, 1);
	p++;

	memcpy(pkt->head_data, p, pkt->head_len);
	p += pkt->head_len;
}

void print_abnormal_packet(ABNORMAL_PACKET pkt) {
	printf("timeStamp = %ld\n", pkt.timeStamp);
	printf("protocol_type = %02x | EGP_ID = %d", pkt.protocol_type, pkt.EGP_ID);
	printf(" | port = %d | head_len = %d\n", pkt.port, pkt.head_len);
	printf("datalinklayer_len = %d | networklayer_len = %d | transportlayer_len = %d\n", pkt.datalinklayer_len, pkt.networklayer_len, pkt.transportlayer_len);
}

int get_head_info(ABNORMAL_PACKET *pkt, unsigned char *data) {
	int len = 0;
	unsigned short type;
	unsigned char next_head;
	int expansion_len;
	unsigned char transportlayer_head_len;
	
	pkt->datalinklayer_len = 14;
	pkt->networklayer_len = 0;
	pkt->transportlayer_len = 0;
	
	unsigned char *p = data;
	p += 12;
	memcpy(&type, p, 2);
	type = ntohs(type);
	if(type != 0x86DD) {
		printf("this packet is not ipv6, not supported now! type = %02x\n", type);
		return -1;
	}
	len += 14;
	p += 2;
	
	p += 6;
	memcpy(&next_head, p, 1);
	len += 40;
	p += 34;
	pkt->networklayer_len += 40;
	
	while(next_head != 6 && next_head != 17 && next_head != 58 && next_head != 89 && next_head != 132) {
		if(next_head == 0 || next_head == 43 || next_head == 60) {
			//逐跳选项首部, 路由扩展首部
			memcpy(&next_head, p, 1);
			p += 1;
			memcpy(&expansion_len, p, 1);
			len += (expansion_len*8+8);
			if(len > MAX_DATA_SIZE) {
				printf("逐跳选项首部, 路由扩展首部太大, expansion_len = %d\n", expansion_len);
				return -1;
			}
			p += (expansion_len*8+8-1);
			pkt->networklayer_len += (expansion_len*8+8);
		} else if(next_head == 44) {
			//分段扩展首部
			memcpy(&next_head, p, 1);
			p += 8;
			len += 8;
			pkt->networklayer_len += 8;
		} else if(next_head == 51) {
			//身份认证扩展首部
			memcpy(&next_head, p, 1);
			p += 1;
			memcpy(&expansion_len, p, 1);
			expansion_len = (expansion_len+2) * 4;
			len += expansion_len;
			if(len > MAX_DATA_SIZE) {
				printf("身份认证扩展首部太大, expansion_len = %d\n", expansion_len);
				return -1;
			}
			p += (expansion_len-1);
			pkt->networklayer_len += expansion_len;
		} else {
			printf("unknown expansion-header, not supported now!\n");
			return -1;
		}
	}
	
	if(next_head == 6) {
		//tcp
		if(len+12 > MAX_DATA_SIZE) {
			printf("tcp header error, len = %d\n", len+12);
			return -1;
		}
		p += 12;
		memcpy(&transportlayer_head_len, p, 1);
		len += (transportlayer_head_len*4);
		transportlayer_head_len = transportlayer_head_len>>4;
		pkt->transportlayer_len += (transportlayer_head_len*4);
	} else if(next_head == 17) {
		//udp
		len += 8;
		pkt->transportlayer_len += 8;
	} else if(next_head == 58) {
		//icmpv6
		len += 4;
		pkt->transportlayer_len += 4;
	} else if(next_head == 89) {
		//ospf
		len += 20;
		pkt->transportlayer_len += 20;
	} else if(next_head == 132) {
		//sctp
		len += 12;
		pkt->transportlayer_len += 12;
	} else {
		printf("unknown transportlayer_header, not supported now!\n");
		return -1;
	}
	
	if(len > MAX_DATA_SIZE) {
		printf("get_head_info error, len = %d\n", len);
		return -1;
	}
	memcpy(pkt->head_data, data, len);
	return len;
}

void addInList(OAP_Head* h, int port, unsigned char *data) {
	OAP_Node* p = h;
	while(p->next != 0) {
		p = p->next;
	} 
	OAP_Node* node = (OAP_Node*) malloc(sizeof(OAP_Node));
	node->port = port;
	memcpy(node->data, data, 1514);
	node->next = 0;
	p->next = node;
}

OAP_Node* getFromList(OAP_Head* h) {
	OAP_Node* ret = h->next;
	if(ret == 0) return 0;
	h->next = ret->next;
	return ret;
}
