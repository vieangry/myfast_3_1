#include "net.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

int send_msg(int sock, unsigned char *buf, int len, int port ,char* ip) {
	int ret = 0, tmp;
	struct sockaddr_in6 hostaddr;
	hostaddr.sin6_family = AF_INET6;
	hostaddr.sin6_port = htons(port);
	inet_pton(AF_INET6, ip, (void*)&hostaddr.sin6_addr);
	socklen_t addrlen = sizeof(hostaddr);

    while(len > ret) {
        tmp = sendto(sock, buf+ret, len-ret, 0, (struct sockaddr *)&hostaddr, addrlen);
        if(-1 == tmp) {
            printf("error occurs in Send()\n");
            return -1;
        }
        ret += tmp;
    }
    return ret;
}

int recv_msg(int sock, void *buf, int len) {
	int ret = 0, tmp;
    while(len != ret) {
        tmp = recvfrom(sock, buf+ret, len-ret, 0, 0, 0);
        if(0 > tmp && errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
            printf("error occurs in Recv()\n");
            return -1;
        } else if(0 == tmp) {
            return 0;
        } else if(0 > tmp && (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) {
		continue;
	}
        ret += tmp;
    }
    return ret;
}

int get_server_socket(int port) {
	int sock;
	struct sockaddr_in6 hostaddr;
	memset(&hostaddr, 0, sizeof(hostaddr));
	hostaddr.sin6_family = AF_INET6;
	hostaddr.sin6_port = htons(port);
	hostaddr.sin6_addr = in6addr_any;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if(-1 == sock) {
		printf("error occurs in socket()\n");
		return -1;
	}

	if(bind(sock, (struct sockaddr*)&hostaddr, sizeof(hostaddr)) == -1) {
		printf("error occurs in bind()\n");
		close(sock);
		return -1;
	}

	return sock;
}

int get_client_socket() {
	int sock;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if(-1 == sock) {
		printf("error occurs in socket()\n");
		return -1;
	}

	return sock;
}


int find(int *a,int key,int low,int high){
	int mid;
	if(low>=high){
		return -1;
	}else{
		mid= (low+high)/2;
		if(a[mid]==key){
			return mid;
		}else if(a[mid]>key){
			return find(a,key,low,mid-1);
		}	else{
			return find(a,key,mid+1,high);
		}
	}
}

int find_insert(int *a,int key,int low,int high){
	int mid;
	if(low>high){
		return -1;
	}else if(low==high){
		return low+1;
	}else{
		mid= (low+high)/2;
		if(a[mid]==key){
			return 0;
		}else if(a[mid]>key){
			return find_insert(a,key,low,mid-1);
		}	else{
			return find_insert(a,key,mid+1,high);
		}
	}
}

unsigned int ELFHash(unsigned char* str,int len)
{
   unsigned int hash = 0;
   unsigned int x    = 0;
   unsigned int i    = 0;
   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << 4) + (*str);
      if((x = hash & 0xF0000000L) != 0)
      {
         hash ^= (x >> 24);
      }
      hash &= ~x;
   }
   return hash;
}


void sort_insert(int *a,int ip,int *max){
	if(*max==0){
		a[0]=ip;
		(*max)++;
		return;
	}
	if(*max==1){
		if(ip>a[0]){
			a[1]=ip;
			(*max)++;
		}else{
			a[1]=a[0];
			a[0]=ip;
			(*max)++;
		}
		return;
	}
	int ret,i;
	ret=find_insert(a,ip,0,(*max)-1);
	if(ret>0){
		for(i=(*max)+1;i>ret;i--){
					a[i]=a[i-1];
		}
		a[ret%1000000]=ip;
		(*max)++;
	}
}

int ip_cmp(unsigned char *ip_src,unsigned char *ip_dst){
	unsigned char local_ip[16];
	unsigned char mask_ip[8];
	unsigned char mask_ip_src[8];
	unsigned char mask_ip_dst[8];
	inet_pton(AF_INET6, IP,local_ip);
	memcpy(mask_ip,local_ip,8);
	memcpy(mask_ip_src,ip_src,8);
	memcpy(mask_ip_dst,ip_dst,8);
	int hash_src,hash_dst,hash_local;
	hash_src=ELFHash(mask_ip_src,8);
	hash_dst=ELFHash(mask_ip_dst,8);
	hash_local=ELFHash(mask_ip,8);
	printf("\nhash_dst:%d,%d,%d\n",hash_local,hash_src,hash_dst);
	if((hash_local!=hash_src)&&(hash_local!=hash_dst)){
		return 1;
	}
	return 0;
}

//获取当前系统时间
long getcurrenttime(){
	struct timeval tv;
	gettimeofday(&tv,NULL);//tv.tv_sec秒   tv.tv_usec毫秒
	return tv.tv_sec;
}

//ipv6地址比较
int ipv6_equal(unsigned char *ip1,unsigned char *ip2){
	printf("进入ipv6_equal\n");
  unsigned char *p1=ip1;
  unsigned char *p2=ip2;
	int i;
  for(i=0;i<16;i++){
    if(*p1!=*p2){
      return -1;
    }else{
      p1++;p2++;
    }
  }printf("出ipv6_equal\n");
  return 0;
}
void printf_ipv6(unsigned char *addr){
	char strptr[40];
	inet_ntop(AF_INET6,addr,strptr,sizeof(strptr));
	printf("(ip_src:%s)",strptr);
}
