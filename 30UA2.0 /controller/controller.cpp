
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <vector>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <sys/time.h>
#include "data_struct.h"
#include "net.h"
#include "comm.h"
using namespace std;

int alert=0;
void stop(int signo) {
  close(sock);
  close(send_sock);
  printf("已经关闭socket\n");
  exit(0);
}
int main(int argc, char *argv[])
{
  signal(SIGINT,stop);
  int len,have_sendto_e=0;
	unsigned char* msg;
	unsigned char flag;
  char flag_type;//报文来自东南那边的标志
  vector<unsigned char*> alert_v;
  vector<unsigned char*> alert_cancel_v;
  send_sock=get_client_socket();
	sock = get_server_socket(PORT_WITH_DEFENSEC);
	while(1) {
    if(have_sendto_e==0&&alert>0&&atack_type!=0){
      //发送告警信息到防御执行器
      if(send_msg(send_sock, &atack_type, 1, DEFENCE_E_IP, DEFENCE_E_PORT)>0){
        have_sendto_e=1;
        printf("send a alert to defene_e\n");
      }
    }
		recv_msg(sock, &len, 4);
		msg = (unsigned char*)malloc(len);
		recv_msg(sock, msg, len);
    memcpy(&flag_type, msg, 1);
    if(flag_type== 0x12){
      printf("type msg\n");
      memcpy(&atack_type, msg+2, 1);//暂时认为atack_type在第三个char,且只发一条
      send_msg(send_sock,msg, sizeof(msg),DISPLAY_IP, DISPLAY_PORT);
      printf("send a atack_type to display\n");
    }
		memcpy(&flag, msg+4, 1);
		printf("len = %d, flag = %02x\n", len, flag);

		if(flag == ALERT_TYPE) {
      alert++;
      printf("alert msg:%d\n",alert);
      ALERT_PACKET type1_struct;
  		decode_alert_packet(&type1_struct, msg);
  		//print_alert_packet(type1_struct);
      alert_v.push_back(msg);

		} else if(flag == ALERT_CANCEL_TYPE) {
      alert--;
      printf("alert cancel msg:%d\n",alert);
      ALERT_CANCEL_PACKET type2_struct;
  		decode_alert_cancel_packet(&type2_struct, msg);
  		//print_alert_cancel_packet(type2_struct);
      alert_cancel_v.push_back(msg);
      if(alert==0&&atack_type!=0){
        //发送解除告警到展示台
        vector<unsigned char *>::iterator it;
        it=alert_cancel_v.begin();
        while(it!=alert_cancel_v.end()){
          send_msg(send_sock,*it, sizeof(*it),DISPLAY_IP, DISPLAY_PORT);
          printf("send a alert_cancel to display\n");
          it = alert_cancel_v.erase(it);
        }
        //发送解除告警信息到防御执行器
        atack_type=0;
        send_msg(send_sock, &atack_type, 1, DEFENCE_E_IP, DEFENCE_E_PORT);
        printf("send a alert cancel to defene_e\n");
      }
      if(alert==0){
        have_sendto_e=0;
        alert_cancel_v.clear();
        alert_v.clear();
      }

		} else if(flag == ABNORMAL_PACKET_TYPE) {
			//printf("abnormal msg\n");
      ABNORMAL_PACKET type3_struct;
  		decode_abnormal_packet(&type3_struct, msg);
  		//print_abnormal_packet(type3_struct);
      if(alert>0&&atack_type!=0){
        //发送异常报文到数据库
        send_msg(send_sock, msg, len, DATABASE_IP, DATABASE_PORT);
        printf("send a abnormal pkt to database\n");
        //发送告警到展示台
        vector<unsigned char *>::iterator it;
        it=alert_v.begin();
        while(it!=alert_v.end()){
          send_msg(send_sock,*it, sizeof(*it),DISPLAY_IP, DISPLAY_PORT);
          printf("send a alert to display\n");
          it = alert_v.erase(it);
        }
      }

      free(msg);

		}else{
      printf("error msg\n");
    }

    if(alert<0||alert>MAX_EPG){
      printf("error because of alert<0||alert>MAX_EPG\n");
    }
	}
	return 0;
}
