#!/bin/bash

# Usage: dal_ks_initd.sh /etc/dal-ks-init/dal_ks_initd.conf
# First argument is the config file of dal_ks_initd service

if [ ! -f "$1" ]; then
    echo 'Config file is missing!'
    exit 1;
fi

DAL_TOOL="/usr/sbin/DAL-Tool"

if [ ! -x "$DAL_TOOL" ]; then
    echo 'DAL-Tool not installed!'
    exit 1;
fi

# Need to change this SD UUID to the one associated with the SD in use 
INTEL_SD_UUID='56784321abcddcbafefeabc123fde765'

# Get path to Keystore.dalp from XML config file
APPLET_FILE=$(grep '<appletDalpPath>' $1 | cut -f2 -d">" | cut -f1 -d"<")
APPLET_UUID=$(grep '<appletId>' $1 | cut -f2 -d">" | cut -f1 -d"<")

# Get hash-file name
APPLET_HASH_FILE="$APPLET_FILE".sha256

# Get OEM SD UUID
OEM_SD_UUID=$("$DAL_TOOL" listSD -s | egrep -iv "$INTEL_SD_UUID")

# Check if appet is installed
APPLET_INSTALLED=$("$DAL_TOOL" listTA -id "$OEM_SD_UUID" -s | \
	grep -ic "$APPLET_UUID")

# Check hash of installed applet
if [ "$APPLET_INSTALLED" -eq 1 ] && [ -f "$APPLET_HASH_FILE" ]; then
    sha256sum -c --status "$APPLET_HASH_FILE"

    if [ $? -eq 0 ]; then
        JHI_INIT_ONLY='--jhi_init_only'
    fi
fi

# (Re-)install the applet and/or initialize JHI
/usr/sbin/dal_ks_initd $1 $JHI_INIT_ONLY

STATUS=$?

if [ -z $JHI_INIT_ONLY ] && [ $STATUS -eq 0 ]; then
# We get here if either hash-file is missing OR applet hash does not match
# AND applet update finished successfully
    sha256sum "$APPLET_FILE" > "$APPLET_HASH_FILE"

    STATUS=$?
    if [ $? -ne 0 ]; then
        echo "Failed to save applet hash to file."
    fi
fi

exit $STATUS
