FROM ubuntu:20.04

ARG HOMEDIR=/home/ctf

RUN apt-get update
RUN apt-get install -y gcc gcc-multilib socat
sudo dock
ENV HOMEDIR=$HOMEDIR
RUN useradd -d $HOMEDIR -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR $HOMEDIR

COPY repeat_your_beat.c $HOMEDIR
RUN gcc -m32 -fno-stack-protector -o $HOMEDIR/repeat_your_beat $HOMEDIR/repeat_your_beat.c

COPY encrypted_text.txt $HOMEDIR
RUN chown ctf:ctf -R $HOMEDIR

USER ctf

EXPOSE 1337

ENTRYPOINT ["sh", "-c", "while true; do socat TCP-LISTEN:1337,fork,reuseaddr, exec:'/home/ctf/repeat_your_beat',stderr; sleep 1; done"]
