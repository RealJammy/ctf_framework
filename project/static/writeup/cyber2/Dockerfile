FROM ubuntu:20.04

ARG HOMEDIR=/home/ctf

RUN apt-get update
RUN apt-get install -y gcc gcc-multilib socat patchelf wget binutils
RUN apt-get install -y xz-utils
ENV HOMEDIR=$HOMEDIR
RUN useradd -d $HOMEDIR -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR $HOMEDIR
RUN mkdir -p $HOMEDIR/temp
RUN wget "http://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.31-0ubuntu9.1_i386.deb" -O $HOMEDIR/temp/pkg.deb
RUN ar x $HOMEDIR/temp/pkg.deb --output $HOMEDIR/temp
RUN tar xf $HOMEDIR/temp/data.tar.xz
RUN cp $HOMEDIR/lib/i386-linux-gnu/libc-2.31.so $HOMEDIR/lib/i386-linux-gnu/ld-2.31.so $HOMEDIR
RUN rm -rf usr/ etc/

COPY repeat_your_beat.c $HOMEDIR
RUN gcc -w -fno-stack-protector -m32 -o $HOMEDIR/repeat_your_beat $HOMEDIR/repeat_your_beat.c
RUN patchelf --set-interpreter $HOMEDIR/lib/i386-linux-gnu/ld-linux.so.2 --replace-needed libc.so.6 $HOMEDIR/libc-2.31.so $HOMEDIR/repeat_your_beat

COPY encrypted_text.txt $HOMEDIR
RUN chown ctf:ctf -R $HOMEDIR

USER ctf

EXPOSE 1337

ENTRYPOINT ["sh", "-c", "while true; do socat TCP-LISTEN:1337,fork,reuseaddr, exec:'/home/ctf/repeat_your_beat',stderr; sleep 1; done"]
