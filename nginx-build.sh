#!/bin/sh
(
mkdir nginx-build
cd nginx-build &&
export NGINX_VERSION=1.15.7 &&
wget --no-check-certificate -O ngx_vts.zip https://github.com/vozlt/nginx-module-vts/archive/master.zip && unzip -o ngx_vts.zip &&
wget --no-check-certificate -O ngx_dynamic_upstream.zip https://github.com/cubicdaiya/ngx_dynamic_upstream/archive/master.zip && unzip -o ngx_dynamic_upstream.zip &&
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && tar xf nginx-${NGINX_VERSION}.tar.gz &&
cd nginx-${NGINX_VERSION} &&
./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --user=nginx \
        --group=nginx \
        --build=Ubuntu \
        --http-log-path=/var/log/nginx/access.log \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
        --add-module=../ngx_dynamic_upstream-master \
        --add-module=../nginx-module-vts-master &&
make -j2 && make install
)
