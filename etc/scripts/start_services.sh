#!/bin/bash

function startApacheLinux () {
  sudo systemctl start apache2 > /dev/null 2>&1
}

function startPostgreSQLLinux () {
  sudo systemctl start postgresql > /dev/null 2>&1
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
