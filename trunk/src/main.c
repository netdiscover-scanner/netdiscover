/***************************************************************************
 *            main.c
 *
 *  Sun Jul  3 07:35:24 2005
 *  Copyright  2005  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
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
#define VERSION "0.3-beta4"

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "ifaces.h"
#include "screen.h"


/* Threads data structure */
struct t_data {
	char *disp;
	char *sip;
	int autos;
};


void start_sniffer_thread(struct t_data *datos);
void start_arp_thread(struct t_data *datos);
void *sniffer_thread(void *arg);
void *inject_arp(void *arg);
void *screen_refresh(void *arg);
void scan_range(char *disp, char *sip);
void usage();

/* Last octect of ips scaned in fast mode */
/* Add new networks if needed here */
char *fast_ips[] = { "1", "100", "254", NULL};

/* Common local networks to scan */
/* Add new networks if needed here */
char *common_net[] = {
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


pthread_t injection, sniffer, screen;
int fastmode, pcount, node, ssleep;
long sleept;

/* main, what is this? */
int main(int argc, char **argv)
{
	int c;
	int esniff = 0;
	int erange = 0;
	struct t_data datos;
	
	datos.sip = NULL;
	datos.disp = NULL;
	datos.autos = 0;
	sleept = 99;
	node = 67;
	pcount = 1;
	
	current_network = (char *) malloc ((sizeof(char)) * 16);
	sprintf(current_network,"Starting.");
	
	/* Fetch parameters */
	while ((c = getopt(argc, argv, "i:s:r:n:c:pSfh")) != EOF)
	{
		switch (c)
		{
			case 'i':
				datos.disp = (char *) malloc (sizeof(char) * strlen(optarg));
				sprintf(datos.disp, "%s", optarg);
				break;
				
			case 'p':
				esniff = 1;
				break;
			
			case  's':
				sleept = atol(optarg);
				break;
			
			case  'S':
				ssleep = 1;
				break;
			
			case  'c':
				pcount = atoi(optarg);
				break;
			
			case  'n':
				node = atoi(optarg);
				break;
			
			case  'r':
				datos.sip = (char *) malloc (sizeof(char) * strlen(optarg));
				sprintf(datos.sip, "%s", optarg);
				erange = 1;
				break;
			
			case  'f':
				fastmode = 1;
				break;
			
			case 'h':
				usage(argv[0]);
				exit(1);
				break;
			
			default:
				break;
		}
	}

	/* Check for uid 0 */
	if ( getuid() && geteuid() )
	{
		printf("You must be root to run this.\n");
		exit(1);
	}
	
	/* If no iface was specified, autoselect one */
	if (datos.disp == NULL)
	{
		datos.disp = pcap_lookupdev(errbuf);
	
		if (datos.disp == NULL)
		{
			printf("Couldn't find default device: %s\n", errbuf);
			exit(1);
		}
	}
	
	lnetInit(datos.disp);
	init_lists();
	system("clear");
	
	if ( (erange == 1) )
	{
		if (pthread_create(&screen, NULL, screen_refresh, (void *)NULL))
			perror("Could not create thread");
		if (pthread_create(&sniffer, NULL, start_sniffer, (void *)&datos))
			perror("Could not create thread");
		
		start_arp_thread(&datos);
		pthread_join(sniffer,NULL);
		pthread_join(injection,NULL);
	}
	else if (esniff ==  1)
	{
		if (pthread_create(&screen, NULL, screen_refresh, (void *)NULL))
			perror("Could not create thread");
		if (pthread_create(&sniffer, NULL, start_sniffer, (void *)&datos))
			perror("Could not create thread");
		
		current_network = "(passive)";
		pthread_join(sniffer,NULL);
	}
	else
	{
		datos.autos = 1;
		
		if (pthread_create(&screen, NULL, screen_refresh, (void *)NULL))
			perror("Could not create thread");
		if (pthread_create(&sniffer, NULL, start_sniffer, (void *)&datos))
			perror("Could not create thread");
		
		start_arp_thread(&datos);
		pthread_join(sniffer,NULL);
		pthread_join(injection,NULL);
	}


	return 0;
}


void start_arp_thread(struct t_data *datos)
{
	
	if (pthread_create(&injection, NULL, inject_arp, (void *)datos))
		perror("Could not create thread");
	
}


void *screen_refresh(void *arg)
{
	
	while (1==1)
	{
		print_screen();
		sleep(1);
	}
	
}


void *sniffer_thread(void *arg)
{
	//struct t_data *datos = (struct t_data *)arg;
	//start_sniffer(datos->disp);
	return NULL;
}


/* Inject ARP Replys to the network */
void *inject_arp(void *arg)
{	
	struct t_data *datos;
		
	datos = (struct t_data *)arg;
	sleep(2);
	
	if ( datos->autos != 1 )
	{
		scan_range(datos->disp, datos->sip);
	}
	else
	{
		int x = 0;
		
		while (common_net[x] != NULL)
		{
			scan_range(datos->disp, common_net[x]);
			x += 1;
		}
		
	}
	
	sprintf(current_network,"Finished!");
	lnetDestroy();
	
	return NULL;
}


/* Scan a /24 network */
void scan_net(char *disp, char *sip)
{
	int x, j;
	char *test, *fromip;
	
	test = (char *) malloc ((sizeof(char)) * 16);
	fromip = (char *) malloc ((sizeof(char)) * 16);
	
	sprintf(fromip,"%s.%i", sip, node);
	
	for (x=0;x<pcount;x++)
	{
	
		/* Check if fastmode is enabled */
		if (fastmode != 1)
		{
			for (j=1; j<255; j++)
			{
				sprintf(test,"%s.%i", sip, j);
				ForgeArp(fromip, test, disp);
				
				if (ssleep != 1)
				{
					/* sleep time */
					if (sleept != 99)
						usleep(sleept * 1000);
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
				ForgeArp(fromip, test, disp);
				j++;
				
				if (ssleep != 1)
				{
					/* sleep time */
					if (sleept != 99)
						usleep(sleept * 1000);
					else
						usleep(1 * 1000);
				}
			}
			
		}
		
		if (ssleep == 1)
		{
			if (sleept != 99)
				usleep(sleept * 1000);
			else
				usleep(1 * 1000);
		}
	
	}
}


/* Scan range, using arp requests */
void scan_range(char *disp, char *sip)
{
	int i, k, e;
	const char delimiters[] = ".,/";
	char *a, *b, *c, *d;
	char *tnet, *net;

	net = (char *) malloc ((sizeof(char)) * 16);
	tnet = (char *) malloc ((sizeof(char)) * 19);
	
	sprintf(tnet, "%s", sip);
	a = strtok (tnet, delimiters); /* 1st ip octect */
	b = strtok (NULL, delimiters); /* 2nd ip octect */
	c = strtok (NULL, delimiters); /* 3rd ip octect */
	d = strtok (NULL, delimiters); /* 4th ip octect */
	e = atoi(strtok (NULL, delimiters)); /* Subnet mask */

	
	/* Scan class C network */
	if ( e == 24)
	{
		sprintf(net, "%s.%s.%s", a, b, c);
		sprintf(current_network,"%s.0/%i", net, e);
		scan_net(disp, net);
		
	}/* Scan class B network */
	else if ( e == 16)
	{
		for (i=0; i<256; i++)
		{
			sprintf(net, "%s.%s.%i", a, b, i);
			sprintf(current_network,"%s.%s.%i.0/%i", a, b, i, e);
			scan_net(disp, net);
		}
		
	} /* Scan class A network */
	else if ( e == 8)
	{
		for (k=0; k<256; k++)
		{
			for (i=0; i<256; i++)
			{
				sprintf(net, "%s.%i.%i", a, k, i);
				sprintf(current_network,"%s.%i.%i.0/%i", a, k, i, e);
				scan_net(disp, net);
			}
		}
	}
	else
	{
		system("clear");
		printf("Network range must be 0.0.0.0/8 , /16 or /24\n");
		exit(1);
	}
	
}


void usage(char *comando)
{
	printf("Netdiscover %s [Active/passive reconnaissance tool]\n"
		"Written by: Jaime Penalba <jpenalbae@gmail.com>\n\n"
		"Usage: %s -i device [-r range | -p] [-s time] [-n node] [-c count] [-f] [-S]\n"
		"  -i device: your network device\n"
		"  -r range: scan a given range instead of auto scan. 192.168.6.0/24,/16,/8\n"
		"  -p passive mode do not send anything, only sniff\n"
		"  -s time: time to sleep between each arp request (miliseconds)\n"
		"  -c count: number of times to send each arp reques (for nets with packet loss)\n"
		"  -n node: last ip octet used for scanning (from 2 to 253)\n"
		"  -S enable sleep time supression betwen each request (hardcore mode)\n"
		"  -f enable fastmode scan, saves a lot of time, recommended for auto\n\n"
		"If -p or -r arent enabled, netdiscover will scan for common lan addresses\n",
		VERSION, comando);
}
