FROM kalilinux/kali-linux-docker

RUN apt update && apt install -y postgresql \
								 apache2 \
								 python-pip \
								 python-dev \
								 build-essential \
								 git \
								 metasploit-framework

RUN git clone https://github.com/NullArray/AutoSploit.git && pip install shodan blessings
COPY database.yml /root/.msf4/database.yml
WORKDIR AutoSploit
EXPOSE 80 443 4444

ENTRYPOINT ["python", "autosploit.py"]
#ENTRYPOINT ["bash"]
