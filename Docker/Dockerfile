FROM kalilinux/kali-linux-docker

RUN apt update \
 && apt install -y \
			apache2 \
			build-essential \
			git \
			metasploit-framework \
			postgresql \
			python-dev \
			python-pip

RUN git clone https://github.com/NullArray/AutoSploit.git \
 && pip install -r AutoSploit/requirements.txt

COPY database.yml /root/.msf4/database.yml

WORKDIR AutoSploit

EXPOSE 80 443 4444

ENTRYPOINT ["python", "autosploit.py"]
# ENTRYPOINT ["bash"]
