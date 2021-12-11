#define _CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string>
#include <setjmp.h>
#include <winsock2.h>

#define HOURS_IN_DAY 86400
#pragma comment(lib,"ws2_32")

/* IPV4 header */
typedef struct
{
	uint8_t   ver_hlen;   /* Header version and length (dwords). */
	uint8_t   service;    /* Service type. */
	uint16_t  length;     /* Length of datagram (bytes). */
	uint16_t  ident;      /* Unique packet identification. */
	uint16_t  fragment;   /* Flags; Fragment offset. */
	uint8_t   timetolive; /* Packet time to live (in network). */
	uint8_t   protocol;   /* Upper level protocol (UDP, TCP). */
	uint16_t  checksum;   /* IP header checksum. */
	uint32_t  src_addr;   /* Source IP address. */
	uint32_t  dest_addr;  /* Destination IP address. */

} IpHdr;

typedef struct {
	uint8_t dest[6];
	uint8_t src[6];
} MacAddr;

const char* HexString(int );
BOOL GetInterfaces(pcap_if_t**);
BOOL GetInterfaceType(pcap_if_t**, const char*, char*, size_t);
BOOL DumpToFile(char*, char* , ULONGLONG);
void CheckUDP(u_char**);
void GetMac(u_char*,const char*);
void GetIP(uint32_t *addr, const char* type);


int main()
{
	WSAData wsadata;

	int iRes = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (iRes)
	{
		ExitProcess(-1);
	}

	pcap_if_t* ifaces = NULL;
	BOOL bStatus;
	char iface[MAX_PATH] = {0};
	const char* filename = HexString(30);

	bStatus = GetInterfaces(&ifaces);
	(bStatus) ? puts("Got interfaces") : puts("Cannot get interfaces");

	bStatus = GetInterfaceType(&ifaces, "wi-fi", iface, MAX_PATH);
	(bStatus) ? puts("Wifi interface hooked") : puts("Wifi interface not hooked");
	pcap_freealldevs(ifaces);

	bStatus = DumpToFile(iface, (char*)filename, 600000);
	(bStatus) ? printf("Dumped to file %s successfully\n",filename) : puts("Failed to dump to file");

	return 0;
}


const char* HexString(int num)
{
	srand((unsigned int)time(NULL));
	static std::string buff;
	char *tmp = new char[10];

	for (int i = 0; i < num; i++)
	{
		memset(tmp, 0, 10);
		snprintf(tmp,10,"%x",rand()%255);
		buff.append(tmp);
	}
	buff.append(".pcap");
	return buff.c_str();
}

BOOL GetInterfaces(pcap_if_t **alldevs)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	RtlSecureZeroMemory(errbuf, PCAP_ERRBUF_SIZE);
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,alldevs, errbuf) == -1)
	{
		printf("%s",errbuf);
		return FALSE;
	}
	return TRUE;
}

BOOL GetInterfaceType(pcap_if_t** alldevs,const char* Type,char* buff,size_t len)
{
	pcap_if_t* d;
	char* lower;
	for (d = *alldevs; d != NULL; d = d->next)
	{
		lower = AnsiLower(d->description);
		if (strstr(lower, Type) != NULL)
		{
			strncpy(buff,d->name,len);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL DumpToFile(char* dev,char* filename,ULONGLONG Duration)
{
	pcap_t* capture;
	pcap_dumper_t* dumpfile;
	pcap_pkthdr* header;
	u_char* pkt_data;
	int res = -1;
	ULONGLONG tick = GetTickCount64();
	capture = pcap_open_live(dev, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);
	if (capture == NULL)
	{
		return FALSE;
	}

	dumpfile = pcap_dump_open(capture, filename);
	if (dumpfile == NULL)
	{
		return FALSE;
	}

	while ((res = pcap_next_ex(capture, &header, (const u_char**)&pkt_data)) >= 0)
	{
		if (GetTickCount64() - tick <= (Duration*1000))
		{
			if (res == 0)
				continue;
			CheckUDP(&pkt_data);
			pcap_dump((unsigned char*)dumpfile, header, pkt_data);
		}
		else {
			pcap_dump_close(dumpfile);
			break;
		}
	}
	return TRUE;
}

void CheckUDP(u_char** pkt_data)
{
	size_t macSize = sizeof(MacAddr);
	IpHdr *iphdr;
	MacAddr *macaddr;
	uint8_t ipver;
	uint8_t hdrlen;

	macaddr = (MacAddr*)(*pkt_data);
	iphdr = (IpHdr*)(*(pkt_data) + macSize);

	ipver =  iphdr->ver_hlen >> 1;
	hdrlen = iphdr->ver_hlen & 0x0F;

	GetMac(macaddr->src,"Src");
	GetMac(macaddr->dest, "Dest");
	/*printf("\nSource mac: %s\nDestination mac: %s",GetMac(macaddr->src),GetMac(macaddr->dest));*/
	printf("\nIp version %u\nhdrlen %u bytes\n", ipver, hdrlen*4);
	printf("\nPacket Identification 0x%x", ntohs(iphdr->ident));
	uint32_t tmp = (iphdr->src_addr); /* Fix improper Ip display issue */
	GetIP(&tmp,"Src");

	return;
}

void GetMac(u_char* addr,const char *type)
{
	char mac[18];
	uint8_t vals[6] = { 0 };
	for (int i = 0; i < 6; i++)
	{
		vals[i] = *(addr + i);
	}
	snprintf
	(
		mac, 18, 
		"%x:%x:%x:%x:%x:%x",
		vals[0],vals[1],
		vals[2],vals[3],
		vals[4],vals[5]
	);
	printf("%s Mac: %s\n",type, mac);
}

void GetIP(uint32_t *addr, const char* type)
{
	char ip[20];
	uint8_t ip_div[4] = {0};
	for (int j = 0; j < 4; j++)
	{
		ip_div[j] = *(addr + j);
	}

	snprintf
	(
		ip,20,
		"%d:%d:%d:%d",
		ip_div[0],ip_div[1],
		ip_div[2],ip_div[3]
	);

	printf("%s IP: %s", type, ip);
}