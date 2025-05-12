/***************************************************************************
 *            main.c
 *
 *  Sun Jul  3 07:35:24 2005
 *  Copyright 2005-2016 Jaime Penalba Estebanez <jpenalbae@gmail.com>
 *  Copyright 2006      Guillaume Pratte <guillaume@guillaumepratte.net>
 *  Copyright 2007-2008 Gustavo Chain
 *  Copyright 2009      Janusz Uzycki <j.uzycki@elproma.com.pl>
 *  Copyright 2019-2021 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
 *  Copyright 2021      Brendan Coles <bcoles@gmail.com>
 *  Copyright 2022      Till Zimmermann <tzimmermann@uos.de>
 *  Copyright 2024      VBrawl <konstantosjim@gmail.com>
 *
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#define _GNU_SOURCE

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>

#include <stdint.h>
#include <arpa/inet.h>

#include "ifaces.h"
#include "screen.h"
#include "fhandle.h"
#include "misc.h"
#include "../config.h"

#define RPATH  "%s/.netdiscover/ranges"
#define FPATH  "%s/.netdiscover/fastips"


extern void parseable_scan_end();
void *inject_arp(void *arg);
void *screen_refresh(void *arg);
void *parsable_screen_refresh(void *arg);
void scan_range(char *disp, char *sip);
void usage();


/* Last octect of ips scaned in fast mode */
/* Add new addr if needed here */
char **fast_ips;
char *dfast_ips[] = { "1", "2", "100", "200", "254", NULL};

/* Common local networks to scan */
/* Add new networks if needed here */
char **common_net;
char *dcommon_net[] = {
   "192.168.0.0/16",
   "172.16.0.0/16",
   "172.26.0.0/16",
   "172.27.0.0/16",
   "172.17.0.0/16",
   "172.18.0.0/16",
   "172.19.0.0/16",
   "172.20.0.0/16",
   "172.21.0.0/16",
   "172.22.0.0/16",
   "172.23.0.0/16",
   "172.24.0.0/16",
   "172.25.0.0/16",
   "172.28.0.0/16",
   "172.29.0.0/16",
   "172.30.0.0/16",
   "172.31.0.0/16",
   "10.0.0.0/8",
   NULL
};


pthread_t injection, sniffer, screen, keys;

/* Command line flags */
int flag_fast_mode;
int flag_repeat_scan;
int flag_network_octect;
int flag_supress_sleep;
int flag_ignore_files;
int flag_auto_scan;
long flag_sleep_time;


/* Read control keys */
void *keys_thread(void *arg)
{
   while ( 1 == 1 )
      read_key();
}

// Convert IP string to uint32_t
uint32_t ip_to_int(const char *ip) {
    struct in_addr addr;
    inet_aton(ip, &addr);
    return ntohl(addr.s_addr);
}

// Convert uint32_t to IP string
void int_to_ip(uint32_t ip, char *buf) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    strcpy(buf, inet_ntoa(addr));
}


/* main, fetch params and start */
int main(int argc, char **argv)
{
   int c;
   int flag_passive_mode = 0;
   int flag_scan_range = 0;
   int flag_scan_list = 0;
   int flag_assume_root = 0;
   int no_parsable_header = 0;
   char *plist = NULL;
   char *mlist = NULL;

   /* Config file handling vars */
   char *home, *path;

   struct t_data datos;

   /* Some default values for the program options.  */
   datos.source_ip = NULL;
   datos.interface = NULL;
   datos.pcap_filter = NULL;
   flag_sleep_time = 99;
   flag_network_octect = 67;
   flag_repeat_scan = 1;
   flag_auto_scan = 0;

   /* Globals defined in screen.h */
   parsable_output = 0;
   continue_listening = 0;

   current_network = (char *) malloc ((sizeof(char)) * 19);
   sprintf(current_network, "Starting.");

   /* Fetch parameters */
   while ((c = getopt(argc, argv, "i:s:r:l:m:n:c:F:pRSfdPNLh")) != EOF)
   {
      switch (c)
      {
         case 'i':   /* Set the interface */
            datos.interface = (char *) malloc (sizeof(char) * (strlen(optarg) + 1));
            sprintf(datos.interface, "%s", optarg);
            break;

         case 'p':   /* Enable passive mode */
            flag_passive_mode = 1;
            break;

         case  's':  /* Set sleep time */
            flag_sleep_time = atol(optarg);
            break;

         case  'S':  /* Enable sleep supression */
            flag_supress_sleep = 1;
            break;

         case  'c':  /* Set no. of times to repeat the scan */
            flag_repeat_scan = atoi(optarg);
            break;

         case  'n':  /* Set las used octect */
            flag_network_octect = atoi(optarg);
            break;

         case  'r':  /* Set the range to scan */
            datos.source_ip = (char *) malloc (sizeof(char) * strlen(optarg) + 1);
            sprintf(datos.source_ip, "%s", optarg);
            flag_scan_range = 1;
            break;

         case 'R': /* Assume user has the required capabilities (Don't run any checks) */
            flag_assume_root = 1;
            break;

         case 'l':   /* Scan ranges on the given file */
            plist = (char *) malloc (sizeof(char) * (strlen(optarg) + 1));
            sprintf(plist, "%s", optarg);
            flag_scan_list = 1;
            break;

         case 'm':   /* Scan MACs on the given file */
            mlist = (char *) malloc (sizeof(char) * (strlen(optarg) + 1));
            sprintf(mlist, "%s", optarg);
            break;

         case  'f':  /* Enable fast mode */
            flag_fast_mode = 1;
            break;

         case 'F':  /* Edit pcap filter */
            datos.pcap_filter = (char *) malloc (sizeof(char) * (strlen(optarg) + 1));
            sprintf(datos.pcap_filter, "%s", optarg);
            break;

         case 'd':   /* Ignore home config files */
            flag_ignore_files = 1;
            break;

         case 'P':   /* Produces parsable output (vs interactive screen) */
            parsable_output = 1;
            break;

         case 'N':   /* Do not print header under parsable mode */
            no_parsable_header = 1;
            break;

         case 'L':   /* Continue to listen in parsable output mode after active scan is completed */
            parsable_output = 1;
            continue_listening = 1;
            break;

	 default:
	    printf("\n"); /* continues... */

         case 'h':   /* Show help */
            usage(argv[0]);
            exit(1);
            break;
      }
   }

   if (optind < argc) {
      printf("Invalid extra argument: %s\n\n", argv[optind]);
      usage(argv[0]);
      exit(1);
   }


   /* Check for uid 0 */
   if(!flag_assume_root) {
     if ( getuid() && geteuid() )
     {
        printf("You must be root to run this.\n");
        exit(1);
     }
   }

   /* If no iface was specified, autoselect one. exit, if no one available */
   if (datos.interface == NULL)
   {
      pcap_if_t *devices = NULL;

      if (pcap_findalldevs(&devices, errbuf) != 0) {
         printf("Couldn't find capture devices: %s\n", errbuf);
         exit(1);
      }

      if (devices == NULL || devices->name == NULL) {
         printf("Couldn't find suitable capture device: %s\n", errbuf);
         exit(1);
      }

      datos.interface = strdup(devices->name);
      pcap_freealldevs(devices);
   }

   /* Check whether user config files are either disabled or can be found */
   if ((flag_ignore_files != 1) && (home = getenv("HOME")) == NULL)
   {
      printf("Couldn't figure out users home path (~). Please set the $HOME "
         "environment variable or specify -d to disable user configuration files.\n");
      exit(1);
   }

   /* Load user config files or set defaults */
   if (flag_ignore_files != 1)
   {
   
      /* Read user configured ranges */
      path = (char *) malloc (sizeof(char) * (strlen(home) + strlen(RPATH) + 1));
      sprintf(path, RPATH, home);

      if ((common_net = fread_list(path)) == NULL)
         common_net = dcommon_net;
      free(path);

      /* Read user configured ips */
      path = (char *) malloc (sizeof(char) * (strlen(home) + strlen(FPATH) + 1));
      sprintf(path, FPATH, home);

      if((fast_ips = fread_list(path)) == NULL)
         fast_ips = dfast_ips;
      free(path);
      
   } else {
   
      /* Set defaults */
      common_net = dcommon_net;
      fast_ips = dfast_ips;
      
   }

   /* Read range list given by user if specified */
   if (flag_scan_list == 1) {
      if ((common_net = fread_list(plist)) == NULL) {
         printf("File \"%s\" containing ranges, cannot be read.\n", plist);
         exit(1);
      }
   }

   /* Read Mac list of known hosts */
   if (mlist != NULL) {
      if (load_known_mac_table(mlist) < 0) {
         printf("File \"%s\" containing MACs and host names, cannot be read.\n", mlist);
         exit(1);
      }
   }

   /* Init libnet, data layers and screen */
   inject_init(datos.interface);
   _data_reply.init();
   _data_request.init();
   _data_unique.init();
   init_screen();

   /* Init mutex */
   data_access = (pthread_mutex_t *)malloc(sizeof (pthread_mutex_t));
   pthread_mutex_init(data_access, NULL);

   /* If no mode was selected, enable auto scan */
   if ((flag_scan_range != 1) && (flag_passive_mode != 1))
      flag_auto_scan = 1;

   /* Start the execution */
   if (parsable_output) {

      if (!no_parsable_header)
         _data_unique.print_simple_header();

   } else {
      int retsys = system("clear");
      if (retsys == -1){ printf("clear system call failed"); }
      pthread_create(&screen, NULL, screen_refresh, (void *)NULL);
      pthread_create(&keys, NULL, keys_thread, (void *)NULL);
   }

   pthread_create(&sniffer, NULL, start_sniffer, (void *)&datos);

   if (flag_passive_mode == 1) {
      current_network = "(passive)";
      pthread_join(sniffer,NULL);

   } else {
      if (pthread_create(&injection, NULL, inject_arp, (void *)&datos))
         perror("Could not create injection thread");

      pthread_join(sniffer,NULL);
   }

   if(datos.pcap_filter != NULL)
	   free(datos.pcap_filter);

   return 0;
}


/* Refresh screen function called by screen thread */
void *screen_refresh(void *arg)
{
    while (1==1) {
        print_screen();
        sleep(1);
    }
}


/* Start the arp injection on the given network device */
void *inject_arp(void *arg)
{
   struct t_data *datos;

   datos = (struct t_data *)arg;
   sleep(2);

   /* Scan the given range, or start the auto scan mode */
   if ( flag_auto_scan != 1 ) {
      scan_range(datos->interface, datos->source_ip);

   } else {
      int x = 0;

      while (common_net[x] != NULL) {
         scan_range(datos->interface, common_net[x]);
         x++;
      }
   }

   /* Wait for last arp replys and mark as scan finished */
   sleep(2);
   sprintf(current_network, "Finished!");
   inject_destroy();

   /* If parseable output is enabled, print end and exit */
   if(parsable_output)
      parseable_scan_end();

   return NULL;
}


/* Scan 255 hosts network */
void scan_net(char *disp, char *sip)
{
   int x, j;
   char test[16], fromip[16];

   sprintf(fromip,"%s.%i", sip, flag_network_octect);

   /* Repeat given times */
   for (x=0; x<flag_repeat_scan; x++)
   {

      /* Check if fastmode is enabled */
      if (flag_fast_mode != 1)
      {
         for (j=1; j<255; j++)
         {
            sprintf(test,"%s.%i", sip, j);
            forge_arp(fromip, test, disp);

            /* Check sleep time supression */
            if (flag_supress_sleep != 1)
            {
               /* Sleep time */
               if (flag_sleep_time != 99)
                  usleep(flag_sleep_time * 1000);
               else
                  usleep(1 * 1000);
            }
         }
      }
      else
      {
         j = 0;

         while (fast_ips[j] != NULL)
         {
            sprintf(test,"%s.%s", sip, fast_ips[j]);
            forge_arp(fromip, test, disp);
            j++;

            /* Check sleep time supression */
            if (flag_supress_sleep != 1)
            {
               /* Sleep time */
               if (flag_sleep_time != 99)
                  usleep(flag_sleep_time * 1000);
               else
                  usleep(1 * 1000);
            }
         }
      }

      /* If sleep supression is enabled, sleep each 255 hosts */
      if (flag_supress_sleep == 1)
      {
         /* Sleep time */
         if (flag_sleep_time != 99)
            usleep(flag_sleep_time * 1000);
         else
            usleep(1 * 1000);
      }

   }
}

/* Scan range, using arp requests */
void scan_range(char *disp, char *cidr)
{
    char ip_str[20], *slash;
    int prefix;
    uint32_t ip, netmask, network, broadcast, start_ip, end_ip;
    char target_ip[16], fromip[16];
    int x;

    // Copy and split IP / prefix 
    strncpy(ip_str, cidr, sizeof(ip_str)-1);
    ip_str[sizeof(ip_str)-1] = '\0';
    slash = strchr(ip_str, '/');

    if (slash == NULL) {
        prefix = 24; // default
    } else {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 1 || prefix > 30) {
            printf("\nERROR: Invalid CIDR prefix '%d' (must be between 1 and 30)\n\n", prefix);
            exit(1);
        }
    }

    ip = ip_to_int(ip_str);
    netmask = (prefix == 32) ? 0xFFFFFFFF : (~0U << (32 - prefix));
    network = ip & netmask;
    broadcast = network | ~netmask;

    start_ip = network + 1;
    end_ip = broadcast - 1;

    // Att current_network to show actual prefix
    sprintf(current_network, "%s/%d", ip_str, prefix);

    for (x = 0; x < flag_repeat_scan; x++)
    {
        for (uint32_t i = start_ip; i <= end_ip; i++)
        {
            int_to_ip(i, target_ip);
            int_to_ip(start_ip, fromip); 

            forge_arp(fromip, target_ip, disp);

            if (flag_supress_sleep != 1)
            {
                if (flag_sleep_time != 99)
                    usleep(flag_sleep_time * 1000);
                else
                    usleep(1 * 1000);
            }
        }

        if (flag_supress_sleep == 1)
        {
            if (flag_sleep_time != 99)
                usleep(flag_sleep_time * 1000);
            else
                usleep(1 * 1000);
        }
    }
}

/* Print usage instructions */
void usage(char *comando)
{
   printf("Netdiscover %s [Active/passive ARP reconnaissance tool]\n"
      "Written by: Jaime Penalba <jpenalbae@gmail.com>\n\n"
      "Usage: %s [-i device] [-r range | -l file | -p] [-m file] [-F filter] "
      "[-s time] [-c count] [-n node] [-dfPLNS]\n"
      "  -i device: your network device\n"
      "  -r range: scan a given range instead of auto scan. 192.168.6.0/24,/16,/8\n"
      "  -l file: scan the list of ranges contained into the given file\n"
      "  -p passive mode: do not send anything, only sniff\n"
      "  -m file: scan a list of known MACs and host names\n"
      "  -F filter: customize pcap filter expression (default: \"arp\")\n"
      "  -s time: time to sleep between each ARP request (milliseconds)\n"
      "  -c count: number of times to send each ARP request (for nets with packet loss)\n"
      "  -n node: last source IP octet used for scanning (from 2 to 253)\n"
      "  -d ignore home config files for autoscan and fast mode\n"
      "  -R assume user is root or has the required capabilities without running any checks\n"
      "  -f enable fastmode scan, saves a lot of time, recommended for auto\n"
      "  -P print results in a format suitable for parsing by another program and stop after active scan\n"
      "  -L similar to -P but continue listening after the active scan is completed\n"
      "  -N Do not print header. Only valid when -P or -L is enabled.\n"
      "  -S enable sleep time suppression between each request (hardcore mode)\n\n"
      "If -r, -l or -p are not enabled, netdiscover will scan for common LAN addresses.\n",
      VERSION, comando);
}
