#!/bin/bash

# Script for generation "oui.h" file (netdiscover program at
#   http://nixgeneration.com/~jaime/netdiscover/
#
# Obtain data from internet source at:
# lynx -source  http://standards.ieee.org/regauth/oui/oui.txt >oui.txt
#
# Syntax: oui.txt2oui.h_netdiscover
#
# Script generate src/oui.h file.
#
# 16-May-2009 Frantisek Hanzlik <franta@hanzlici.cz> (Original author)
# 07-Jun-2001 Larry Reznick <lreznick@rezfam.com> (fixes & code clean)
#**********************************************************************
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#

JA=${0##*/}
DATE=$(date +'%Y%m%d')
ORIGF=oui.txt
DSTD=src
DSTF=oui.h
URL="http://standards.ieee.org/develop/regauth/oui/oui.txt"
TMPF=$ORIGF-$DATE
AWK="gawk"
#AWK="mawk"
#AWK="awk"

[ -d "$DSTD" ] || { echo "$JA: Destdir \"$DSTD\" not exist!"; exit 1; }
#if ! [ -f "$TMPF" -a -s "$TMPF" ]; then
#   echo "Trying download \"$ORIGF\" with lynx..."
#   if ! lynx -source $URL >"$TMPF"; then
#      echo "Trying download \"$ORIGF\" with elinks..."
#      if ! elinks -source $URL >"$TMPF"; then
#         echo "Trying download \"$ORIGF\" with wget..."
#         if ! wget --quiet --output-document="$TMPF" $URL; then
#            echo "$JA: Cann't obtain \"$URL\"!"
#            exit 1
#         fi
#      fi
#   fi
#else
#   echo "\"$TMPF\" already exist, skipping download..."
#fi
if ! [ -f "$TMPF" -a -s "$TMPF" ]; then
  echo -n "Trying download \"$ORIGF\" with lynx..."
  if [[ -x /usr/bin/lynx ]]; then
    lynx -source $URL >"$TMPF"
  else
     echo -n " with elinks..."
     if [[ -x /usr/bin/elinks ]]; then
       elinks -source $URL >"$TMPF"
     else
        echo " with wget..."
        if [[ -x /usr/bin/wget ]]; then
          wget --quiet --output-document="$TMPF" $URL
        else
          if [[ -x /usr/bin/curl ]]; then
             curl -s $URL >"$TMPF"
          else
             echo "$JA: Can't obtain \"$URL\"!"
             exit 1
          fi
        fi
     fi
  fi
else
   echo -n "\"$TMPF\" already exist, skipping download..."
fi
echo ""

echo "Process oui.txt (\"$TMPF\")..."

# if RS is null string, then records are separated by blank lines...
# but this isn't true in oui.txt

LANG=C grep "base 16" $TMPF | sed "s/\"/'/g" | $AWK --re-interval --assign URL="$URL" '
BEGIN {
	NN = 0;
	printf( \
	  "/*\n" \
	  " * Organizationally Unique Identifier list at date %s\n" \
	  " * Automatically generated from %s\n" \
	  " * For Netdiscover by Jaime Penalba\n" \
	  " *\n" \
	  " */\n" \
	  "\n" \
	  "struct oui {\n" \
	  "   char *prefix;   /* 24 bit global prefix */\n" \
	  "   char *vendor;   /* Vendor id string     */\n" \
	  "};\n" \
	  "\n" \
	  "struct oui oui_table[] = {\n", strftime("%d-%b-%Y"), URL);
}

{
	printf("   { \"%s\", \"", $1);
	for (i=4; i<NF; i++) printf $i " ";
	printf("%s\" },\n", $NF);
	NN++;
}

END {
	printf("   { NULL, NULL }\n};\n\n");
	printf("// Total %i items.\n\n", NN);
}' >"$DSTD/$DSTF"


if [ $? -ne 0 ]; then
  echo "$JA: $TMPF parsing error !"
  exit 1
else
  echo "All OK"
  ls -oh oui.txt-* src/oui.h
fi
