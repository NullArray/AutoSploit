#!/bin/bash

function startApacheLinux () {
  sudo service apache2 start > /dev/null 2>&1
}

function startPostgreSQLLinux () {
  sudo service postgresql start > /dev/null 2>&1
}

function startApacheOSX () {
  sudo apachectl start > /dev/null 2>&1
}

function startPostgreSQLOSX () {
  brew services restart postgresql > /dev/null 2>&1
}

function main () {
  if [ $1 == "linux" ]; then
    startApacheLinux;
    startPostgreSQLLinux;
  elif [ $1 == "darwin" ]; then
    startApacheOSX;
    startPostgreSQLOSX;
  else
    echo "[*] invalid operating system";
  fi
}

main $@;
