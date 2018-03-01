#define PORT_WITH_DEFENSEC 6666
#define PORT_WITH_CLASSIFYE 6665
#define IP_OF_DEFENSEC "2002:da8:6000:306:f8e7:1707:5de0:2503"
#define IP_OF_CLASSIFYE "::1"

int send_msg(int sock, const void *buf, int len, char* ip, int port);

int recv_msg(int sock, void *buf, int len);

int get_server_socket(int port);

int get_client_socket();
