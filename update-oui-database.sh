#!/bin/bash

# update-oui-database.sh
# This script creates the src/oui.h file needed by netdiscover.
#
# Copyright 2016-2022 Joao Eriberto Mota Filho <eriberto@debian.org>
# This file is under GPL-2+ license.
#
# netdiscover was written by Jaime Penalba Estebanez <jpenalbae@gmail.com>
# and is available at https://github.com/netdiscover-scanner/netdiscover
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

VERSION=0.4

# CHANGELOG
#
# v0.4, 2022-02-17, Eriberto
#
# * Add --insecure option to download from
#   http://standards-oui.ieee.org/oui/oui.txt. (Fix #15, again)
#
# v0.3, 2021-11-11, Eriberto
#
# * Change download site from http://standards-oui.ieee.org/oui/oui.txt to
#   https://linuxnet.ca/ieee/oui.txt. (Fix #15)
#
# v0.2, 2020-06-29, Eriberto
#
# * Drop 'sed -z' to execute in macOS.
# * Drop not needed PATH variable, also for macOS.
#
# v0.1, 2016-04-13, Eriberto
#
# * Initial release.


#####################
# Initial variables #
#####################

DATE=$(date +%F | tr -d "-")
DATE2=$(date +%F)
NAME=oui.txt-$DATE
OUIFILE=src/oui.h

# Minimum amount of MAC addresses for check. Is not needed to update this every
# time. The main goal is check if a generated file was corrupted.
# To calculate, use "cat `oui_file` | grep "base 16" | wc -l"
# Last definition on 2021-11-11.
MINIMUM_MAC=30500

# URL to download
URL=https://standards-oui.ieee.org/oui/oui.txt

# Insecure URL
IURL=http://standards-oui.ieee.org/oui/oui.txt

####################
# Help and version #
####################

if [ "$1" = "--help" ] || [ "$1" = "-h" ]
then
    printf "\nupdate-oui-database.sh $VERSION\n\n"
    printf "Usage: ./update-oui-database.sh [OPTIONS]\n\n"
    printf "  --no-download   Do not download the oui.txt. Use an already downloaded version.\n"
    printf "  --insecure      Use an insecure address, started with http, instead of https.\n"
    printf "  --help, -h      Show this help.\n"
    printf "  --version, -v   Show version.\n\n"
    printf "If running without options, the program will download the oui.txt file from\ndefault place.\n\n"
    printf "Default place:  $URL\n"
    printf "Insecure place: $IURL\n"
    exit 0
fi

if [ "$1" = "--version" ] || [ "$1" = "-v" ]
then
    printf "\nupdate-oui-database.sh\n\n"
    printf "Version $VERSION\n\n"
    exit 0
fi


######################
# Check for dos2unix #
######################

# Insecure for Legacy Purposes 
if [ "$1" = "--insecure" ]
then
    dos2unix -V > /dev/null 2> /dev/null || { printf "\nYou need dos2unix command to use this script.\n\n"; exit 1; }

    # Redefining $URL to use insecure
    URL="$IURL"
fi

##################
# Check for gzip #
##################

gzip -V > /dev/null 2> /dev/null || { printf "\nYou need gzip command to use this script.\n\n"; exit 1; }

####################
# OUI.txt download #
####################

# Check if .gz is present

URLEND=${URL: -3}
GZ=""

if [ "$URLEND" = ".gz" ]; then GZ=".gz"; fi

# Search for downloaders

DOWN=0

if [ "$1" = "--no-download" ]; then DOWN=no; fi

if [ "$DOWN" = "0" ]; then axel -V > /dev/null 2> /dev/null && DOWN="axel -ao ${NAME}${GZ}"; fi
if [ "$DOWN" = "0" ]; then curl -V > /dev/null 2> /dev/null && DOWN="curl -Lo ${NAME}${GZ}"; fi
if [ "$DOWN" = "0" ]; then wget -V > /dev/null 2> /dev/null && DOWN="wget -O ${NAME}${GZ}"; fi
if [ "$DOWN" = "0" ]; then printf "\nYou need axel (faster!), wget or curl to use this script.\n\n" && exit 1; fi

# Download the oui.txt

if ( [ -f "${NAME}.gz" ] || [ -f "$NAME" ] ) && [ "$DOWN" != "no" ]
then
    printf "\nThe file $NAME (with or without .gz) already exists. To run this script, remove it or use --no-download option.\n\n"
    exit 1
elif [ ! -f "${NAME}.gz" ] && [ ! -f "$NAME" ] && [ "$DOWN" = "no" ]
then
    printf "\nThe file $NAME (with or without .gz) is missing. To download it don't use --no-download option.\n\n"
    exit 1
elif [ "$DOWN" != "no" ]
then
    printf "\n\nDownloading oui.txt from $URL\n"
    printf "Downloader to be used: $(echo $DOWN | cut -d" " -f1)\n\n"
    $DOWN $URL
fi

# Unzip if needed

if [ -f "${NAME}.gz" ]
then
    echo "Found ${NAME}.gz. Unpacking..."
    gunzip "${NAME}.gz"
fi

# Final check and conversion to Unix (if needed)

TOTAL_MAC=$(cat $NAME | grep "base 16" | wc -l)

if [ "$TOTAL_MAC" -lt "$MINIMUM_MAC" ]
then
    printf "\nThe file $NAME seems to be corrupted. There are $TOTAL_MAC MAC addresses. However, over the $MINIMUM_MAC addresses were expected.\n\n"
    exit 1
fi

# insecure for legacy purposes
if [ "$1" = "--insecure" ]
then
    dos2unix -q $NAME
fi


######################
# Building src/oui.h #
######################

printf "\n\nBuilding the $OUIFILE.\n"

# The header

cat << EOT > $OUIFILE
/*
 * Organizationally Unique Identifier list downloaded on $DATE2
 * Automatically generated from $URL
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
  tr '\n' '#' | sed 's/#/" },#/g' | tr '#' '\n' >> $OUIFILE

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
