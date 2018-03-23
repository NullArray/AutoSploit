#!/bin/bash

echo "  ____  __ __  ______   ___   _____ ____  _       ___  ____  ______ ";
echo " /    ||  |  ||      | /   \ / ___/|    \| |     /   \|    ||      |";
echo "|  o  ||  |  ||      ||     (   \_ |  o  ) |    |     ||  | |      |";
echo "|     ||  |  ||_|  |_||  O  |\__  ||   _/| |___ |  O  ||  | |_|  |_|";
echo "|  _  ||  :  |  |  |  |     |/  \ ||  |  |     ||     ||  |   |  |  ";
echo "|  |  ||     |  |  |  |     |\    ||  |  |     ||     ||  |   |  |  ";
echo "|__|__| \__,_|  |__|   \___/  \___||__|  |_____| \___/|____|  |__|  ";
echo "                                                                    ";

function installDebian () {
    sudo apt-get update;
    sudo apt-get -y install git python2.7 python-pip postgresql apache2;
    pip2 install requests psutil;
    installMSF;
}

function installFedora () {
    sudo yum -y install git python-pip;
    pip2 install requests psutil;
    installMSF;
}

function installOSX () {
  sudo /usr/sbin/apachectl start;
  brew doctor;
  brew update;
  brew install postgresql;
  brew services start postgresql;
  installMSF;
}

function installMSF () {
    if [[ ! "$(which msfconsole)" = */* ]]; then
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
            chmod 755 msfinstall && \
            ./msfinstall;
        rm msfinstall;
    fi
}

function install () {
    case "$(uname -a)" in
        *Debian*|*Ubuntu*)
            installDebian;
            ;;
        *Fedora*)
            installFedora;
            ;;
        *Darwin*)
            installOSX;
            ;;
        *)
            echo "Unable to detect operating system that is compatible with AutoSploit...";
            ;;
    esac
    echo "";
    echo "Installation Complete";
}

install;
