#define PORT 2017

#define IP "2001:da8:6000:306:f8e7:1707:5de0:2502"//本EPG 的IP-->掩码

int send_msg(int sock, unsigned char *buf, int len, int port,char *ip);

int recv_msg(int sock, void *buf, int len);

int get_server_socket(int port);

int get_client_socket();
//int get_server_socket(int port, int maxsock);
//int get_client_socket(int port, char *ip);

void sort_insert(int *a,int ip,int *max);

int find_insert(int *a,int key,int low,int high);

int find(int *a,int key,int low,int high);

unsigned int ELFHash(unsigned char* str,int len);

int ip_cmp(unsigned char *ip_src,unsigned char *ip_dst);

long getcurrenttime();

int ipv6_equal(unsigned char *ip1,unsigned char *ip2);

void printf_ipv6(unsigned char *addr);
