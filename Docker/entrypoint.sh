#!/bin/bash

/etc/init.d/postgresql start
/etc/init.d/apache2 start
cd AutoSploit/
export PATH=$PATH:/opt/metasploit-framework

python autosploit.py
