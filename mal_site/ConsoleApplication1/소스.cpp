#define _CRT_SECURE_NO_WARNINGS



#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAXBUF 0xFFFF
#define MAXURL 4096

/*
* URL and blacklist representation.
*/
typedef struct
{
	char *domain;
	char *uri;
} URL, *PURL;
typedef struct
{
	UINT size;
	UINT length;
	PURL *urls;
} BLACKLIST, *PBLACKLIST;

/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;
typedef struct
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;

const char block_data[] =
"HTTP/1.1 200 OK\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n"



"\r\n"
"<!doctype html>\n"
"<html>\n"
"\t<head>\n"
"\t\t<title>BLOCKED!</title>\n"
"\t</head>\n"
"\t<body>\n"
"\t\t<h1>BLOCKED WTF!</h1>\n"
"\t\t<hr>\n"
"\t\t<p>This URL has been blocked!</p><script>alert('WTF!');</script>\n"
"\t</body>\n"
"</html>\n";

/*
* Prototypes
*/

char domain[255];
static void PacketInit(PPACKET packet);
static int __cdecl UrlCompare(const void *a, const void *b);
static int UrlMatch(PURL urla, PURL urlb);
static PBLACKLIST BlackListInit(void);
static void BlackListInsert(PBLACKLIST blacklist, PURL url);
static void BlackListSort(PBLACKLIST blacklist);
static BOOL BlackListMatch(PBLACKLIST blacklist, PURL url);
static void BlackListRead(PBLACKLIST blacklist, const char *filename);
static BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data,
	UINT16 len);

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payload_len;
	PACKET reset0;
	PPACKET reset = &reset0;
	PACKET finish0;
	PPACKET finish = &finish0;
	PDATAPACKET blockpage;
	UINT16 blockpage_len;
	PBLACKLIST blacklist;
	INT16 priority = 404;       // Arbitrary.
	FILE *log_ouput;
	char input_f[50] = {0, };
	log_ouput = fopen("log.txt", "a");
	printf("	File format is domain.xxx\n");
	printf("	Press enter,default input file is mal_site.txt\n");
	printf("	Filtering input File name : ");
	scanf("%[^\n]s",input_f);
	if (*input_f == NULL) {
		sscanf("mal_site.txt","%s",input_f);
	}
	fprintf(log_ouput,"	File is %s\n",input_f);
	printf("	File is %s\n", input_f);
	fclose(log_ouput);
	FILE *file = fopen(input_f,"r");// Read the blacklists.
	if (file == NULL)												//파일이 열리지 않으면 에러
	{
		fprintf(log_ouput, "error: could not open blacklist file %s\n",
			input_f);
		exit(EXIT_FAILURE);
	}
	blacklist = BlackListInit();
	
	BlackListRead(blacklist, input_f);
	
	BlackListSort(blacklist);

	// Initialize the pre-frabricated packets:
	blockpage_len = sizeof(DATAPACKET) + sizeof(block_data) - 1;
	blockpage = (PDATAPACKET)malloc(blockpage_len);
	if (blockpage == NULL)
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	PacketInit(&blockpage->header);
	blockpage->header.ip.Length = htons(blockpage_len);
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh = 1;
	blockpage->header.tcp.Ack = 1;
	memcpy(blockpage->data, block_data, sizeof(block_data) - 1);
	PacketInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketInit(finish);
	finish->tcp.Fin = 1;
	finish->tcp.Ack = 1;

	// Open the Divert device:
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.DstPort == 80 && "     // HTTP (port 80) only
		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, priority, 0
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("\nStart filtering\n");

	// Main loop:
	
	while (TRUE)
	{
		log_ouput = fopen("log.txt", "a");
		
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char*)payload, (UINT16)payload_len))
		{
			// Packet does not match the blacklist; simply reinject it.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		// The URL matched the blacklist; we block it by hijacking the TCP
		// connection.

		// (1) Send a TCP RST to the server; immediately closing the
		//     connection at the server's end.
		reset->ip.SrcAddr = ip_header->SrcAddr;
		reset->ip.DstAddr = ip_header->DstAddr;
		reset->tcp.SrcPort = tcp_header->SrcPort;
		reset->tcp.DstPort = htons(80);
		reset->tcp.SeqNum = tcp_header->SeqNum;
		reset->tcp.AckNum = tcp_header->AckNum;
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		// (2) Send the blockpage to the browser:
		blockpage->header.ip.SrcAddr = ip_header->DstAddr;
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;
		blockpage->header.tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);
		addr.Direction = !addr.Direction;     // Reverse direction.
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,
			NULL))
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		// (3) Send a TCP FIN to the browser; closing the connection at the 
		//     browser's end.
		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data) - 1);
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);
		//printf("block");
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}
		fclose(log_ouput);
	}
}

/*
* Initialize a PACKET.
*/
static void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an empty blacklist.
*/
static PBLACKLIST BlackListInit(void)
{
	PBLACKLIST blacklist = (PBLACKLIST)malloc(sizeof(BLACKLIST));
	UINT size;
	if (blacklist == NULL)
	{
		goto memory_error;
	}
	size = 1024;
	blacklist->urls = (PURL *)malloc(size * sizeof(PURL));
	if (blacklist->urls == NULL)
	{
		goto memory_error;
	}
	blacklist->size = size;
	blacklist->length = 0;

	return blacklist;

memory_error:
	fprintf(stderr, "error: failed to allocate memory\n");
	exit(EXIT_FAILURE);
}

/*
* Insert a URL into a blacklist.
*/
static void BlackListInsert(PBLACKLIST blacklist, PURL url)
{
	if (blacklist->length >= blacklist->size)
	{
		blacklist->size = (blacklist->size * 3) / 2;
		printf("GROW blacklist to %u\n", blacklist->size);
		blacklist->urls = (PURL *)realloc(blacklist->urls,
			blacklist->size * sizeof(PURL));
		if (blacklist->urls == NULL)
		{
			fprintf(stderr, "error: failed to reallocate memory\n");
			exit(EXIT_FAILURE);
		}
	}

	blacklist->urls[blacklist->length++] = url;
}

/*
* Sort the blacklist (for searching).
*/
static void BlackListSort(PBLACKLIST blacklist)
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}

/*
* Match a URL against the blacklist.
*/
static BOOL BlackListMatch(PBLACKLIST blacklist, PURL url)
{
	int lo = 0, hi = ((int)blacklist->length) - 1;

	while (lo <= hi)
	{
		INT mid = (lo + hi) / 2;
		int cmp = UrlMatch(url, blacklist->urls[mid]);
		if (cmp > 0)
		{
			hi = mid - 1;
		}
		else if (cmp < 0)
		{
			lo = mid + 1;
		}
		else
		{
			return TRUE;
		}
	}
	return FALSE;
}


/*
* Read URLs from a file.
*/
static void BlackListRead(PBLACKLIST blacklist, const char *filename)
{
	char domain[MAXURL + 1];
	char uri[MAXURL + 1];
	int c;
	UINT16 i, j;
	PURL url;
	FILE *file = fopen(filename, "r");

	if (file == NULL)
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}

	// Read URLs from the file and add them to the blacklist: 
	while (TRUE)
	{
		while (isspace(c = getc(file)))
			;
		if (c == EOF)
		{
			break;
		}
		if (c != '-' && !isalnum(c))
		{
			while (!isspace(c = getc(file)) && c != EOF)
				;
			if (c == EOF)
			{
				break;
			}
			continue;
		}
		i = 0;
		domain[i++] = (char)c;
		while ((isalnum(c = getc(file)) || c == '-' || c == '.') && i < MAXURL)
		{
			domain[i++] = (char)c;
		}
		domain[i] = '\0';
		j = 0;
		if (c == '/')
		{
			while (!isspace(c = getc(file)) && c != EOF && j < MAXURL)
			{
				uri[j++] = (char)c;
			}
			uri[j] = '\0';
		}
		else if (isspace(c))
		{
			uri[j] = '\0';
		}
		else
		{
			while (!isspace(c = getc(file)) && c != EOF)
				;
			continue;
		}

		printf("ADD %s/%s\n", domain, uri);

		url = (PURL)malloc(sizeof(URL));
		if (url == NULL)
		{
			goto memory_error;
		}
		url->domain = (char *)malloc((i + 1) * sizeof(char));
		url->uri = (char *)malloc((j + 1) * sizeof(char));
		if (url->domain == NULL || url->uri == NULL)
		{
			goto memory_error;
		}
		strcpy(url->uri, uri);
		for (j = 0; j < i; j++)
		{
			url->domain[j] = domain[i - j - 1];
		}
		url->domain[j] = '\0';

		BlackListInsert(blacklist, url);
	}

	fclose(file);
	return;

memory_error:
	fprintf(stderr, "error: memory allocation failed\n");
	exit(EXIT_FAILURE);
}


static BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len)
{
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	URL url = { domain, uri };
	UINT16 i = 0, j;
	BOOL result;
	HANDLE console;

	if (len <= sizeof(post_str) + sizeof(http_host_str))
	{
		return FALSE;
	}
	if (strncmp(data, get_str, sizeof(get_str) - 1) == 0)
	{
		i += sizeof(get_str) - 1;
	}
	else if (strncmp(data, post_str, sizeof(post_str) - 1) == 0)
	{
		i += sizeof(post_str) - 1;
	}
	else
	{
		return FALSE;
	}

	for (j = 0; i < len && data[i] != ' '; j++, i++)
	{
		uri[j] = data[i];
	}
	uri[j] = '\0';
	if (i + sizeof(http_host_str) - 1 >= len)
	{
		return FALSE;
	}

	if (strncmp(data + i, http_host_str, sizeof(http_host_str) - 1) != 0)
	{
		return FALSE;
	}
	i += sizeof(http_host_str) - 1;

	for (j = 0; i < len && data[i] != '\r'; j++, i++)
	{
		domain[j] = data[i];
	}
	if (i >= len)
	{
		return FALSE;
	}
	if (j == 0)
	{
		return FALSE;
	}
	if (domain[j - 1] == '.')
	{
		// Nice try...
		j--;
		if (j == 0)
		{
			return FALSE;
		}
	}
	domain[j] = '\0';
	FILE *log_output;
	log_output = fopen("log.txt", "a");
	fprintf(log_output,"URL %s/%s: ", domain, uri);
	fclose(log_output);
	printf("URL %s : ", domain);
	// Reverse the domain:
	for (i = 0; i < j / 2; i++)
	{
		char t = domain[i];
		domain[i] = domain[j - i - 1];
		domain[j - i - 1] = t;
	}

	// Search the blacklist:
	result = BlackListMatch(blacklist, &url);

	// Print the verdict:
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (result)
	{
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		puts("BLOCKED!");
		FILE *log_output;
		log_output = fopen("log.txt", "a");
		fprintf(log_output, "BLOCKED! \n");
		fclose(log_output);
	}
	else
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		puts("allowed");
		FILE *log_output;
		log_output = fopen("log.txt", "a");
		fprintf(log_output,"allowed! \n");
		fclose(log_output);
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return result;
}

/*
* URL comparison.
*/
static int __cdecl UrlCompare(const void *a, const void *b)
{
	PURL urla = *(PURL *)a;
	PURL urlb = *(PURL *)b;
	int cmp = strcmp(urla->domain, urlb->domain);
	if (cmp != 0)
	{
		return cmp;
	}
	return strcmp(urla->uri, urlb->uri);
}

/*
* URL matching
*/
static int UrlMatch(PURL urla, PURL urlb)
{
	UINT16 i;

	for (i = 0; urla->domain[i] && urlb->domain[i]; i++)
	{
		int cmp = (int)urlb->domain[i] - (int)urla->domain[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->domain[i] == '\0' && urlb->domain[i] != '\0')
	{
		return 1;
	}

	for (i = 0; urla->uri[i] && urlb->uri[i]; i++)
	{
		int cmp = (int)urlb->uri[i] - (int)urla->uri[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->uri[i] == '\0' && urlb->uri[i] != '\0')
	{
		return 1;
	}
	return 0;
}