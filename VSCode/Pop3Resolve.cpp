#include "Pop3Resolve.h"

/* 本函数用于获取数据包中的仅POP3数据 */
int GetPop(const char* FileName, const char* OutputFileName);

/*----------------------
* 用argv接收要处理的文件名
* 文件需要使用绝对路径
* --------------------*/
int main(int args, char* argv[]) {
    char OutputFileName[40];

    if(args < 2) {
        /* 参数小于2个，说明没有传入需要解析的文件，直接返回提示 */
        printf("There is no target file!\nPlease run the app with a file name!\n./Pop3Resolve.out <InputFileName>\n\n");
        return NO_INPUT;
    }
    memset(OutputFileName, 0, sizeof(OutputFileName));
    strncpy(OutputFileName, argv[1], strlen(argv[1])-5);
    GetPop(argv[1], OutputFileName);
    return 0;
}

int GetPop(const char* FileName, const char* OutputFileName) {
    /* fp指定要读取的文件，StrHead指定要保存信息的字符串首地址 */
    /* 定义数据包头 */
    pcap_file_header* FileHeader = (pcap_file_header*)malloc(sizeof(pcap_file_header));
    pcap_pkthdr*    DataHeader = (pcap_pkthdr*)malloc(sizeof(pcap_pkthdr));
    FrameHeader_t*  MacHeader = (FrameHeader_t *)malloc(sizeof(FrameHeader_t));
    IPHeader_t*     IpHeader = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    TCPHeader_t*    TcpHeader = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
    /* 定义文件指针 */
    FILE* InputFile, * OutputFile;
    /* 定义临时变量 */
    /* PopLen代表本次POP3文件的字节数 */
    int DataOffest = 24, PopLen, MacHeaderLen;
    int MailLen, MailCur, ReceiveTag = READY, FileIndex = 0;
    int src_port, dst_port;
    char DataTime[STR_SIZE], MailBuff[BUF_SIZE];
    char src_ip[30], dst_ip[30];


    /* 路径下无该文件，返回并提示错误信息 */
    if((InputFile = fopen(FileName, "r")) == NULL) {
        printf("ERROR - There is no such file named \"%s\"\n", FileName);
        return FILE_OPEN_ERR;
    }

    if(fread(FileHeader, sizeof(pcap_file_header), 1, InputFile) != 1) {
        return NO_PCAP;
    }
    /* 计算当前数据链路帧首部的长度 */
    switch (FileHeader->linktype)
    {
    case ETHERNET:
        /* code */
        MacHeaderLen = ETHER_HEAD;
        break;
    case LINUXCOOKED:
        MacHeaderLen = LINUX_COOKED_CAPTURE_HEAD;
        break;
    }

    /* 遍历数据包 */
    while (fseek(InputFile, DataOffest, SEEK_SET) == 0) {
        /* 初始化空间 */
        memset(DataHeader, 0, sizeof(DataHeader));
        memset(MacHeader, 0, sizeof(MacHeader));
        memset(IpHeader, 0, sizeof(IpHeader));
        memset(TcpHeader, 0, sizeof(TcpHeader));
        memset(MailBuff, 0, sizeof(MailBuff));

        if(fread(DataHeader, 16, 1, InputFile) != 1) {
            printf("File %s's Analyse has finished!\n", FileName);
            break;
        }

        /* 计算下一个数据包的偏移值 */
        DataOffest += (16 + DataHeader->caplen);

        /* 读取pcap包时间戳，转换成标准格式时间 */
        struct tm *timeinfo;
        time_t t = (time_t)(DataHeader->ts.tv_sec);
        timeinfo = localtime(&t);
        strftime(DataTime, sizeof(DataTime), "%Y-%m-%d %H:%M:%S", timeinfo);
        //printf("%s: ", DataTime);

        /* 忽略数据帧头 */
        fseek(InputFile, MacHeaderLen, SEEK_CUR); /* 忽略数据帧头 */

        if(fread(IpHeader, sizeof(IPHeader_t), 1, InputFile) != 1) {
            break;
        }
        inet_ntop(AF_INET, (void *)&(IpHeader->SrcIP), src_ip, 16);
        inet_ntop(AF_INET, (void *)&(IpHeader->DstIP), dst_ip, 16);
        // printf("SourIP: %s, DestIP: %s; ", src_ip, dst_ip);
        if(IpHeader->Protocol != 6) {
            /* 不是TCP，直接跳过 */
            continue;
        }

        if(fread(TcpHeader, sizeof(TCPHeader_t), 1, InputFile) != 1) {
            break;
        }
        /* 注意网络字节序和电脑字节序相反，先转换后比较 */
        src_port = ntohs(TcpHeader->SrcPort);
        dst_port = ntohs(TcpHeader->DstPort);
        // printf("SourPort: %d, DestPort: %d\n", src_port, dst_port);
        if(src_port != 110 || (TcpHeader->Flags)&(u_int8)2 || (TcpHeader->Flags)&(u_int8)1) {
            /* 一定要注意TCP爆头的标志位，只有FIN和SYN为0时才是POP3 */
            /* 不是POP3，直接跳过 */
            continue;
        }

        /* 经过三次过滤，只剩下POP3协议的数据包，进行协议解析 */
        /* POP3报文的总长度 */
        // printf("%s, %d\n", (TcpHeader->Flags)&2 ? "SYN" : "POP3", TcpHeader->Flags);
        PopLen = ntohs(IpHeader->TotalLen) - 40;
        // printf("TCP Segment Length: %d\n", PopLen);
        for (int i = 0; i < PopLen && (MailBuff[i] = fgetc(InputFile)) != EOF; i++);

        if (ReceiveTag == RECEIVE) {
            /* 正在进行数据接受 */
            fwrite(MailBuff, PopLen, 1, OutputFile);
            MailCur += PopLen;
            if(MailCur >= MailLen) {
                ReceiveTag = READY;
                fclose(OutputFile);
                FileIndex++;
            }
        } else {
            /* 因为返回必为+OK，直接忽略；
            假如不是，返回Err，则后面为提示字符 */
            int TempPos = 4;
            MailLen = 0;    MailCur = 0;
            if(MailBuff[TempPos] < '0' || MailBuff[TempPos] > '9') {
                /* 如果是list命令此位置应为/n；只要不为数字则不符合条件，跳过 */
                continue;
            }

            while(MailBuff[TempPos] >= '0' && MailBuff[TempPos] <= '9') {
                MailLen = (MailLen<<3) + (MailLen<<1) + (MailBuff[TempPos]-'0');
                TempPos++;
            }            
            printf("Mail_%d Length is %d.\n", FileIndex, MailLen);
            ReceiveTag = RECEIVE;

            /* 构造目标文件名 */
            char TarFileName[40];
            sprintf(TarFileName, "%s_%d.eml", OutputFileName, FileIndex);
            OutputFile = fopen(TarFileName, "w");

            TempPos += 2;   /* 移动到邮件内容位置 */
            if(TempPos >= PopLen)   {
                /* 后面没有内容，跳过 */
                continue;
            }

            MailCur += PopLen-TempPos;
            fwrite(MailBuff+TempPos, 1, MailCur, OutputFile);
        }
    }

    /* 释放空间 */
    free(DataHeader);
    free(MacHeader);
    free(IpHeader);
    free(TcpHeader);
    return SUCESS;
}