FROM rockylinux:9

ENV DEBIAN_FRONTEND=noninteractive
RUN mkdir /updater

COPY ./ips_updater.py /updater/ips_updater.py

# ✅ entrypoint 추가
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /root

RUN dnf -y install epel-release && \
    dnf config-manager --set-enabled crb && \
    dnf -y install \
    cmake make gcc gcc-c++ git flex bison \
    libpcap-devel pcre-devel \
    procps-ng \
    pcre2-devel libdnet-devel hwloc-devel \
    openssl-devel zlib-devel luajit-devel \
    pkgconf libmnl-devel libunwind-devel \
    libnfnetlink-devel libnetfilter_queue-devel \
    autoconf automake libtool \
    xz-devel libuuid-devel \
    hyperscan hyperscan-devel \
    gperftools-devel \
    wget vim ethtool iproute \
    iptables \                    
    supervisor && \
    dnf clean all

RUN dnf -y install python3 python3-pip && dnf clean all
RUN pip3 install mysql-connector-python

# LibDAQ
RUN git clone https://github.com/snort3/libdaq.git && \
    cd libdaq && ./bootstrap && ./configure && make && make install && \
    ln -s /usr/local/lib/libdaq.so.3 /lib/ && ldconfig

# Snort3
RUN git clone https://github.com/snort3/snort3.git && \
    cd snort3 && export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig && \
    ./configure_cmake.sh --prefix=/usr/local/snort --enable-tcmalloc && \
    cd build && make -j$(nproc) && make install

COPY ./supervisord.conf /etc/supervisord.conf

# ✅ ENTRYPOINT 설정
ENTRYPOINT ["/entrypoint.sh"]
