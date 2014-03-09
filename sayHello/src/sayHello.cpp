#include <stdio.h>
#include <winsock2.h>
#include <pthread.h>

/* pcap */
#include "pcap.h"
#define HAVE_REMOTE
#include "remote-ext.h"

#include "process.h"
#include "sayHello.h"

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];

bool hasEchoKey = false;
u_int echoNo;
u_int echoKey;
u_char echoBuf[45];

int main(int argc, char const *argv[]){
    showVersion();

    getHandle();

    pthread_t echoThread;
    if (pthread_create(&echoThread, NULL, sendEchoThreadFunction, NULL) != 0) {
        fprintf(stderr, "%s\n", "创建线程失败");
        return 0;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    return 0;
}

void showVersion() {
    printf("*******************************************************************************\n"
           "*                                                                             *\n"
           "*                  Ruijie sayHello                                            *\n"
           "*                                                                             *\n"
           "*                  Author: hang                                               *\n"
           "*                                                                             *\n"
           "*                  GitHub: https://github.com/hangim/Ruijie                   *\n"
           "*                                                                             *\n"
           "*                  CopyRight c 2014 hang.im                                   *\n"
           "*                                                                             *\n"
           "*******************************************************************************\n\n"
           );
}

/* * * 打开网卡 * * */
int getHandle() {
    pcap_if_t *alldevs;
    pcap_if_t *d;

    int i = 0;

    /* 获取本机设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    /* 打印列表 */
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s\n", ++i, d->name);
        if (d->description)
            printf("\t(%s)\n", d->description);
        else
            printf("\n");
    }
    
    if (i == 0) {
        fprintf(stderr, "No interfaces found! Make sure WinPcap is installed.\n");
        exit(1);
    }
    
    printf("\nEnter the interface number [1-%d]:", i);

    int inum;
    scanf("%d", &inum);
    if(inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        exit(1);
    }
    
    /* 跳转到选中的适配器 */
    for(d = alldevs, i = 0; i < inum-1; d = d->next, i++);
    
    /* 打开设备 */
    if ((handle= pcap_open(d->name, 50, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        exit(1);
    }
    
    printf("\nlistening on %s...\n\n", d->description);
    
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);
    
    return 0;
}

void *sendEchoThreadFunction(void * threadId) {
    while (true) {
        if (hasEchoKey) {
            Sleep(20000);
            sendEcho();
            printf("\r发送心跳\techoKey = %d\techoNo = %d", echoKey, echoNo);
        }
    }
}

/* * * 发送心跳包 * * */
int sendEcho(){
    echoNo++;

    u_char bt1[4], bt2[4];
    *(u_int *)bt1 = htonl(echoNo + echoKey);
    *(u_int *)bt2 = htonl(echoNo);

    for (int i = 0; i < 4; i++) {
        echoBuf[0x18+i] = encode(bt1[i]);
        echoBuf[0x22+i] = encode(bt2[i]);
    }

    return pcap_sendpacket(handle, echoBuf, 0x2D); // 0x2D=45
}

/* * * 回调函数 * * */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    if (not isEAP(pkt_data))
        return;

    if (isEchoPacket(pkt_data)) {
        if (not hasEchoKey) {
            getEchoBuf(pkt_data);

            getEchoKey(pkt_data);
            hasEchoKey = true;
            printf("抓取心跳\techoKey = %d\techoNo = %d\n\n", echoKey, echoNo);

            FindAndKillProcessByName("8021x.exe");
            printf("结束 8021x.exe 进程\n\n");
        }
        return;
    }
}

/* * * 判断 EAP 扩展认证协议 * * */
bool isEAP(const u_char *pkt_data) {
    return pkt_data[0x0c] == 0x88 and pkt_data[0x0d] == 0x8e;
}

/* * * 判断数据包类型 * * */
bool isEchoPacket(const u_char *pkt_data) {
    return pkt_data[0x0F] == 0xBF; // echo type
}

void getEchoBuf(const u_char *pkt_data) {
    memcpy(echoBuf, pkt_data, 0x2D); // 0x2D = 45
}

/* * * 根据心跳包得到 echoNo 和 echoKey * * */
void getEchoKey(const u_char *pkt_data) {
    u_char cKeyNO[4], cNO[4];
    for (int i = 0; i < 4; i++){
        cKeyNO[i] = encode(pkt_data[0x18+i]);
        cNO[i] = encode(pkt_data[0x22+i]);
    }

    /* 转换为 int */
    u_int iKeyNO = *(u_int *)cKeyNO;
    u_int iNO = *(u_int *)cNO;

    /* 转换为本机序 */
    echoNo = ntohl(iNO);
    echoKey = ntohl(iKeyNO) - echoNo;
}

/* * * 将一个字节的8位颠倒并取反 * * */
u_char encode(u_char base){
    u_char result = 0;
    for (int i=0; i<8; i++){
        result <<= 1;
        result |= base & 0x01;
        base >>= 1;
    }
    return(~result);
}
