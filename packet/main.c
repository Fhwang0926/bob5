#include <arpa/inet.h>
#include <stdio.h>
#include <pcap.h>
#define SIZE_ETHERNET 14

    int main(int argc, char *argv[])
    {



        const struct sniff_ethernet *ethernet; /* The ethernet header */
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
        const char *payload; /* Packet payload */

        u_int size_ip;
        u_int size_tcp;

        char *dev; /* name of the device to use */
        char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
        pcap_t *handle;		/* Session handle */
        struct bpf_program fp;		/* The compiled filter expression */
        char filter_exp[] = "";/* "port 80";	/* The filter expression */
        bpf_u_int32 mask;		/* The netmask of our sniffing device */
        bpf_u_int32 net;		/* The IP of our sniffing device */
        struct pcap_pkthdr *header;	/* The header that pcap gives us */
        const u_char *packet;		/* The actual packet */

        dev = pcap_lookupdev(errbuf);
        printf("\n\n    Start capture packet \n\n");
            /* error checking */
            if(dev == NULL)
            {
                printf("%s\n",errbuf);
                exit(1);
            }
            printf("Device = %s\n",dev);


        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", dev);
            net = 0;
            mask = 0;
        }
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        /* Grab a packet */
        int res;
        int num=0;
        while((res=pcap_next_ex(handle, &header,&packet))>=0)
        {


            print_form(packet, num);
            num++;
            if (res==0) {

                continue;
            }
        }

        /* And close the session */
        pcap_close(handle);
        return(0);
        //end here
    }
    struct tcp_header
    {
        unsigned short source_port;
        unsigned short dest_port;

    };
    struct udp_header
    {
        unsigned short source_port;
        unsigned short dest_port;

    };

    void print_form(const unsigned char *data, int num)
    {

        printf("=========================================================\n");
        printf("================= packet cupture Number :  %d  ==========\n",num);
        printf("=========================================================\n");
        printf("================= Ethernet Frame ========================\n\n");
        printf("---------- MAC Address \n");
        printf("D_MAC = %02x:%02x:%02x:%02x:%02x:%02x\n", data[0],data[1],data[2],data[3],data[4],data[5]);
        printf("S_MAC = %02x:%02x:%02x:%02x:%02x:%02x\n\n", data[6],data[7],data[8],data[9],data[10],data[11]);
    int tmp=(int)data[23];
        printf("---------- IP header \n");
        printf("S_Address = %d.%d.%d.%d\n", data[26],data[27],data[28],data[29]);
        printf("D_Address = %d.%d.%d.%d\n", data[30],data[31],data[32],data[33]);
    switch (tmp) {
        case 1:
            printf("\n---------- ICMP \n");
            break;
        case 2:
            printf("\n----------IGMP \n");
            break;
        case 6:
            printf("\n----------TCP \n");
            struct  tcp_header *th;
            th = (struct tcp_header *)(data+34);
            printf("S_Port Num : %u\n", (u_short)ntohs(th->source_port) );
            printf("D_Port Num : %u\n", (u_short)ntohs(th->dest_port) );
            break;
        case 17:
            printf("\n----------UDP \n");
            struct  udp_header *uh;
            uh = (struct udp_header *)(data+34);
            printf("S_Port Num : %u\n", (u_short)ntohs(uh->source_port) );
            printf("D_Port Num : %u\n", (u_short)ntohs(uh->dest_port) );
            break;
        default:
            printf("Next Protocl is not ICMP,IGMP, TCP, UDP\n");
            break;
        }
    printf("---------- \n\n");

    }
