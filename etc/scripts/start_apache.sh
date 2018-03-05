#!/bin/bash

distribution=`uname -r`
archstring="ARCH"

if [[ $distribution =~ $archstring ]] # compare if we are under arch
then # if yes, launch apachectl
	sudo apachectl > /dev/null 2>&1
else # if not, launch it the debian way
	sudo service apache2 start > /dev/null 2>&1
fi
