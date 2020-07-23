# deb cdrom:[Debian GNU/Linux 7.0 _Kali_ - Official Snapshot i386 LIVE/INSTALL $

# deb cdrom:[Debian GNU/Linux 7.0 _Kali_ - Official Snapshot i386 LIVE/INSTALL $

## Security updates

deb http://http.kali.org/ /kali main contrib non-free
deb http://http.kali.org/ /wheezy main contrib non-free
deb http://http.kali.org/kali kali-dev main contrib non-free
deb http://http.kali.org/kali kali-dev main/debian-installer
deb-src http://http.kali.org/kali kali-dev main contrib non-free
deb http://http.kali.org/kali kali main contrib non-free
deb http://http.kali.org/kali kali main/debian-installer
deb-src http://http.kali.org/kali kali main contrib non-free
deb http://security.kali.org/kali-security kali/updates main contrib non-free
deb-src http://security.kali.org/kali-security kali/updates main contrib non-fr$

فای
#!/bin/bash

function startApacheLinux () {
  # NOTE: if you are running on Arch uncomment this
  #sudo systemctl start apache > /dev/null 2>&1
  # and comment this one out
  sudo systemctl start apache2 > /dev/null 2>&1
}

function startPostgreSQLLinux () {
  sudo systemctl start postgresql > /dev/null 2>&1
}

function main () {
  if [ $1 == "linux" ]; then
    startApacheLinux;
    startPostgreSQLLinux;
  else
    echo "[*] invalid operating system";
  fi
}

main $@;
