#include "../include/fast.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "net.h"
#define mid 189
#define ctoe_port 5555
int sock;
int max=0,node_list=0,alert=0;//alert测试，可先设置为1
int tcp_flood=0,udp_flood=0,icmpv6_flood=0;
typedef struct syn_flood_struct{
  unsigned char IPsrc[16];
  unsigned char IPdst[16];
  long f_time;
  unsigned char heibaiflag;//黑-1；白1；不定0；
}Type_synflood;
typedef struct Node{    /* 定义单链表结点类型 */
    Type_synflood *element;
    struct Node *next;
}Node;
Node *pNode=NULL;

int find_syn(unsigned char *ip_src,unsigned char *ip_dst);
void find_ack(unsigned char *ip_src,unsigned char *ip_dst);
int callback(struct fast_packet *pkt,int pkt_len);

int find_syn(unsigned char *ip_src,unsigned char *ip_dst){
	Node *head=pNode;
	while (head!=NULL&&head->next!=NULL) {
		if(ipv6_equal(head->element->IPsrc, ip_src)==0&&ipv6_equal(head->element->IPdst, ip_dst)==0){
      if(head->element->heibaiflag==0){
				long nowtime=getcurrenttime();
				if(nowtime-head->element->f_time<3){
					head->element->heibaiflag=-1;
				}
			}printf("|heibaiflag:%d|",head->element->heibaiflag);
			return head->element->heibaiflag;
		}
		else{
			head=head->next;
		}
	}
	Type_synflood *flood;
	flood=malloc(sizeof(Type_synflood));
	//flood->IPsrc=ip_src;
	//flood->IPdst=ip_dst;
	memcpy(flood->IPsrc, ip_src, 16);
	memcpy(flood->IPdst, ip_dst, 16);
	flood->f_time=getcurrenttime();
	flood->heibaiflag=0;
  if(head==NULL){
    head=malloc(sizeof(Node));
    head->element=flood;
    head->next=NULL;
    node_list++;
  }else{
    Node *flood_node;
    flood_node=malloc(sizeof(Node));
    flood_node->element=flood;
    flood_node->next=NULL;
  	head->next=flood_node;
    node_list++;
  }
	printf("--------node_list:%d\n",node_list);
  printf("|heibaiflag:%d|",head->element->heibaiflag);
	return flood->heibaiflag;
}

void find_ack(unsigned char *ip_src,unsigned char *ip_dst){
	Node *head=pNode;
	while (head!=NULL&&head->next!=NULL) {
		if(ipv6_equal(head->element->IPsrc, ip_src)==0&&ipv6_equal(head->element->IPdst, ip_dst)==0){
			head->element->heibaiflag=1;
		}else{
			head=head->next;
		}
	}
}

int callback(struct fast_packet *pkt,int pkt_len)
{
	char drop=0;
	unsigned char tcp_type;
	unsigned char ip_src[16];
	unsigned char ip_dst[16];
	unsigned char syn=0,ack=0;
  unsigned short type;//以太网帧类型
	unsigned char n;//next_head
	if(alert==1){
		unsigned char *p;
		p=pkt->data;
		int hash,ret,this_port;//该报文目的端口号
		p += 12;
		memcpy(&type, p, 2);
		type = ntohs(type);
		if(type == 0x86DD) {
			p += 2;
			p += 6;
			memcpy(&n, p, 1);
			p+=2;
			memcpy(ip_src,p,sizeof(ip_src));
      printf_ipv6(ip_src);
			p+=16;
			memcpy(ip_dst,p,sizeof(ip_dst));
      printf_ipv6(ip_dst);
			p+=16;
			while(n==0||n==60||n==43||n==44||n==51||n==50){
				p+=6;
				memcpy(&n,p,1);
				p+=34;
			}
			//printf("head_type:%d\n",n);
			printf("|n:%d|",n);
			if(n==6){
				//tcp
        int src_port=0;
        memcpy(&src_port,p,2);
        src_port=ntohs(src_port);
        printf("(src_port=%d)",src_port);
				p+=2;
				memcpy(&this_port,p,2);
        this_port=ntohs(this_port);
        printf("(this_port=%d)",this_port);
				p+=11;
				memcpy(&tcp_type,p,1);
			}else if(n==17){
				//udp
				p+=2;
				memcpy(&this_port,p,2);
			}
			// else if(n==58){
		  // 	//icmpv6
			// }else if(next_head == 89) {
			// 	//ospf
			// }else{
      //
			// }
			//hash=ELFHash(ip_src,sizeof(ip_src));
			//ret=find(atack_ip,hash,0,max-1);
			if(ip_cmp(ip_src,ip_dst)==1||this_port>=10000){
				drop=1;
        printf("|||因为ip_cmp(ip_src,ip_dst)==1|||");
			}
		}else{
      printf("type != 0x86DD");
      drop=1;printf("因为type != 0x86DD\n");
    }
	}
	//if(drop==0&&tcp_flood==1&&n==6){
	if(type == 0x86DD){//测试
		//将同一源IP，发送频率过高的报文过滤
		//将没有第三次握手的报文过滤
		syn=((tcp_type<<2)&8)>>3;
		ack=((tcp_type<<2)&64)>>6;
		printf("syn:%d--ack:%d\n",syn,ack);
		if(syn==1&&ack==0){
			//找到为黑；白；不定返回firstime，找不到返回-1，并插入
			if(find_syn(ip_src,ip_dst)==-1){
				drop=1;
        printf("因为find_syn(ip_src,ip_dst)==-1\n");
			}
		}
		if(ack==1){
			find_ack(ip_src,ip_dst);

		}
	}
	if(drop==1){
		//pkt->um.discard=1;
		//printf("一条攻击流\n" );
		printf("&");
	}

	if(drop==0){
		//printf("一条正常流\n" );
		printf("*" );
		pkt->um.dstmid=5;
		pkt->um.outport=1;
		pkt->um.pktdst=0;
		fast_ua_send(pkt,pkt_len);
	}

	return 0;
}

void stop(int signo) {
  close(sock);
  printf("已经关闭socket\n");
  exit(0);
}
int main(int argc,char* argv[]){

  int val;
  unsigned int ip;
  sock=get_server_socket(ctoe_port);
  if(sock < 0) {
  printf("can't get right socket\n");
    return -1;
  }
  printf("connect to server successfully!\n");

  /*初始化平台硬件*/
	fast_init_hw(0,0);
  /*UA模块初始化	*/
	fast_ua_init(mid,callback);

	fast_ua_recv();
  signal(SIGINT,stop);
  while(1){
    char atack_type;
		val = recv_msg(sock,&atack_type,1);
		if(val<=0){
			printf("recv_msg error\n");
			continue;
		}
		if(atack_type==0){
			alert=0;
			tcp_flood=0;
			udp_flood=0;
			icmpv6_flood=0;
			printf("get alert cancel\n");
		}else{
			printf("get alert :");
			alert=1;//暂定atack_type的顺序为以下这样
			if(atack_type&1){
				tcp_flood=1;//提取tcp_flood
				printf("---tcp_flood");
			}
			if(atack_type&2){
				udp_flood=1;//提取udp_flood
				printf("---udp_flood");
			}
			if(atack_type&4){
				icmpv6_flood=1;//提取icmpv6_flood
				printf("---icmpv6_flood");
			}
			printf("\n");
		}
  }
  close(sock);
  return 0;
}
