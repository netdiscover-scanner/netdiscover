/***************************************************************************
 *            screen.h
 *
 *  Tue Jul 12 03:22:19 2005
 *  Copyright  2005  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 *
 *  Contributors:
 *   Parsable output by Guillaume Pratte <guillaume@guillaumepratte.net>
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


/* ARP types definitions */
#define NARP_REQUEST 1
#define NARP_REPLY 2

/* Screen modes definitions */
#define SMODE_REPLY 0
#define SMODE_REQUEST 1
#define SMODE_HELP 2
#define SMODE_HOST 3

/* Ohh no, more globals */
char *current_network;
int parsable_output, continue_listening;

/* Structs for arp reply counters */
struct arp_rep_c {
	unsigned int count;
	unsigned int hosts;
	unsigned int length;
};

/* Structs for arp request counters  */
struct arp_req_c {
    unsigned int count;
    unsigned int hosts;
    unsigned int length;
};

/* Structs for unique hosts counters  */
struct host_c {
    unsigned int count;
    unsigned int hosts;
    unsigned int length;
};

/* holds headers packet data */
struct p_header {
	unsigned char smac[6];
	unsigned char dmac[6];
	unsigned int length;
};
 

/* holds arp requests packet data */
struct arp_req_l {
	struct p_header *header;
	char *sip;
	char *dip;
    char *vendor;
    short type;
	unsigned int count;
	struct arp_req_l *next;
};

/* holds arp replys packet data */
struct arp_rep_l {
	struct p_header *header;
	char *sip;
	char *dip;
	char *vendor;
	short type;
	unsigned int count;
	struct arp_rep_l *next;
};

/* holds unique hosts list */
struct host_l {
	struct p_header *header;
	char *sip;
	char *dip;
	char *vendor;
	short type;
	unsigned int count;
	struct host_l *next;
};


/* Screen functions */
void print_screen();
void fill_screen();
void print_header();
void print_parsable_screen();
void print_parsable_line(struct arp_rep_l *);
void print_arp_reply_line(struct arp_rep_l *);
void print_arp_request_line(struct arp_req_l *);
void print_unique_host_line(struct host_l *);
void parsable_output_scan_completed();
void read_key();
void sighandler(int);

/* Functions to handle pointer lists */
void init_lists();
void arprep_add(struct arp_rep_l *);
void arpreq_add(struct arp_req_l *);
void host_add(void *);
