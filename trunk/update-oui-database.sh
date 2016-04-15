#!/bin/bash

# update-oui-database-ng.sh
# This script creates the src/oui.h file needed by netdiscover.
#
# Copyright 2016 Joao Eriberto Mota Filho <eriberto@debian.org>
# This file is under GPL-2+ license.
#
# netdiscover was written by Jaime Penalba Estebanez <jpenalbae@gmail.com>
# and is available at http://nixgeneration.com/~jaime/netdiscover/
#
# License for this script:
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

VERSION=0.1

# CHANGELOG
#
# v0.1, 2016-04-13, Eriberto
#
# * Initial release.


#####################
# Initial variables #
#####################

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DATE=$(date +%F | tr -d "-")
DATE2=$(date +%F)
NAME=oui.txt-$DATE
OUIFILE=src/oui.h

# Minimum amount of MAC addresses for check.
# To calculate, use "cat `oui_file` | grep "base 16" | wc -l"
# Last definition on 2016-04-13.
MINIMUM_MAC=21900

# The original URL[1] redirects to this URL[2].
# [1] http://standards.ieee.org/develop/regauth/oui/oui.txt
# [2] http://standards-oui.ieee.org/oui/oui.txt
URL=http://standards-oui.ieee.org/oui/oui.txt


####################
# Help and version #
####################

if [ "$1" = "--help" ]
then
    printf "\nupdate-oui-database-ng.sh\n\n"
    printf "Usage: ./update-oui-database-ng.sh [OPTIONS]\n\n"
    printf "  --help          Show this help.\n"
    printf "  --no-download   Do not download the oui.txt to use an existent version.\n"
    printf "  --version       Show version.\n"
    exit 0
fi

if [ "$1" = "--version" ]
then
    printf "\nupdate-oui-database-ng.sh\n\n"
    printf "Version $VERSION\n\n"
    exit 0
fi


######################
# Check for dos2unix #
######################

dos2unix -V > /dev/null 2> /dev/null || { printf "\nYou need dos2unix command to use this script.\n\n"; exit 1; }


####################
# OUI.txt download #
####################

# Search for downloaders

DOWN=0

if [ "$1" = "--no-download" ]; then DOWN=no; fi

if [ "$DOWN" = "0" ]; then axel -V > /dev/null 2> /dev/null && DOWN="axel -ao $NAME"; fi
if [ "$DOWN" = "0" ]; then curl -V > /dev/null 2> /dev/null && DOWN="curl -Lo $NAME"; fi
if [ "$DOWN" = "0" ]; then wget -V > /dev/null 2> /dev/null && DOWN="wget -O $NAME"; fi
if [ "$DOWN" = "0" ]; then printf "\nYou need axel (faster!), wget or curl to use this script.\n\n" && exit 1; fi

# Download the oui.txt

if [ -f "$NAME" ] && [ "$DOWN" != "no" ]
then
    printf "\nThe file $NAME already exists. To run this script, remove $NAME or use --no-download option.\n\n"
    exit 0
elif [ ! -f "$NAME" ] && [ "$DOWN" = "no" ]
then
    printf "\nThe file $NAME is missing. To download it, does not use --no-download option.\n\n"
    exit 0
elif [ "$DOWN" != "no" ]
then
    printf "\n\nDownloading oui.txt from $URL\n"
    printf "Downloader to be used: $(echo $DOWN | cut -d" " -f1)\n\n"
    $DOWN $URL
fi

# Final check and conversion to Unix

TOTAL_MAC=$(cat $NAME | grep "base 16" | wc -l)

if [ "$TOTAL_MAC" -lt "$MINIMUM_MAC" ]
then
    printf "\nThe file $NAME seems to be corrupted. There are $TOTAL_MAC MAC addresses. However, over the $MINIMUM_MAC were expected.\n\n"
    exit 0
fi

dos2unix -q $NAME


######################
# Building src/oui.h #
######################

printf "\n\nBuilding the $OUIFILE.\n"

# The header

cat << EOT > $OUIFILE
/*
 * Organizationally Unique Identifier list downloaded on $DATE2
 * Automatically generated from http://standards.ieee.org/develop/regauth/oui/oui.txt
 * For Netdiscover by Jaime Penalba
 *
 */

struct oui {
   char *prefix;   /* 24 bit global prefix */
   char *vendor;   /* Vendor id string     */
};

struct oui oui_table[] = {
EOT

# The MACs

cat $NAME | grep "base 16" | tr '\t' ' ' | tr -s " " | sed 's/(base 16) //' | \
  grep '[0-9A-F]' |  sort | sed 's/ /", "/' | sed 's/^/    { "/' | \
  sed -z 's/\n/" },#/g' | tr '#' '\n' >> $OUIFILE

# Total of MACs

TOTALMAC=$(cat $OUIFILE | egrep "{ .[0-9A-F]" | wc -l)

# The tail

cat << EOT >> $OUIFILE
    { NULL, NULL }
};

// Total $TOTALMAC items.
EOT

printf "Done. $OUIFILE has $TOTALMAC MAC addresses.\n"
# END
