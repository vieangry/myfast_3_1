#include "data_struct.h"
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>  
#include <netinet/if_ether.h>  
#include <net/if.h>  
#include <linux/sockios.h> 
#include <sys/time.h>

int main()
{
	int len;
	unsigned char* msg;
	unsigned char flag;
	int sock = get_server_socket(PORT_WITH_DEFENSEC);
	while(1) {
		recv_msg(sock, &len, 4);
		msg = (unsigned char*)malloc(len);
		recv_msg(sock, msg, len);
		memcpy(&flag, msg, 1);
		printf("len = %d, flag = %02x\n", len, flag);
		if(flag == 0x01) {
			printf("alert msg\n");
		} else if(flag == 0x02) {
			printf("alert cancel msg\n");
		} else if(flag == 0x11) {
			printf("abnormal msg\n");
		}
		free(msg);
	}
	
	return 0;
}
