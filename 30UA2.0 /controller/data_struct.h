#define ALERT_PACKET_MAXSIZE 68
#define ALERT_CANCEL_PACKET_SIZE 2
#define ABNORMAL_PACKET_MAXSIZE 260
#define ALERT_TYPE 0x01
#define ALERT_CANCEL_TYPE 0x11
#define ABNORMAL_PACKET_TYPE 0x02
#define MAX_DATA_SIZE 1514

//告警信息
typedef struct AlertPacket {
	long timeStamp;
	unsigned char protocol_type;//0x01
	unsigned char EGP_ID;
	unsigned char port_status;
	unsigned char reserved;
	short inrate_byte[8];
	short outrate_byte[8];
	short inrate_pkt[8];
	short outrate_pkt[8];
}ALERT_PACKET;

//编码函数，编码为字符串
int encode_alert_packet(ALERT_PACKET pkt, unsigned char* msg);

//解码函数，解码为字符串
void decode_alert_packet(ALERT_PACKET* pkt, unsigned char* msg);

void print_alert_packet(ALERT_PACKET pkt);

//解除告警信息
typedef struct AlertCancelPacket {
	long timeStamp;
	unsigned char protocol_type;//0x11
	unsigned char EGP_ID;
}ALERT_CANCEL_PACKET;

int encode_alert_cancel_packet(ALERT_CANCEL_PACKET pkt, unsigned char* msg);

void decode_alert_cancel_packet(ALERT_CANCEL_PACKET* pkt, unsigned char* msg);

void print_alert_cancel_packet(ALERT_CANCEL_PACKET pkt);

typedef struct AbnormalPacket{
	long timeStamp;//时间戳
	unsigned char protocol_type;
	unsigned char EGP_ID;
	unsigned char port;
	short head_len;
	unsigned char datalinklayer_len;
	unsigned char networklayer_len;
	unsigned char transportlayer_len;
	unsigned char head_data[1514];
}ABNORMAL_PACKET;

int encode_abnormal_packet(ABNORMAL_PACKET pkt, unsigned char* msg);

void decode_abnormal_packet(ABNORMAL_PACKET *pkt, unsigned char* msg);

void print_abnormal_packet(ABNORMAL_PACKET pkt);

//解析ipv6报文
int get_head_info(ABNORMAL_PACKET *pkt, unsigned char *data);

//原始异常报文
typedef struct OriginAbnormalPacket{
	struct OriginAbnormalPacket* next;
	int port;
	unsigned char data[1514];
}OAP_Node, OAP_Head;

void addInList(OAP_Head* h, int port, unsigned char *data);

OAP_Node* getFromList(OAP_Head* h);
