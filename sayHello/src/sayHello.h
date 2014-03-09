typedef unsigned char u_char;
typedef unsigned int u_int;

void showVersion();
int getHandle();
void *sendEchoThreadFunction(void * threadId);
int sendEcho();
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
bool isEAP(const u_char *pkt_data);
bool isEchoPacket(const u_char *pkt_data);
void getEchoBuf(const u_char *pkt_data);
void getEchoKey(const u_char *pkt_data);
u_char encode(u_char base);
