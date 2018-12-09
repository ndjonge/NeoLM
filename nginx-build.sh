#!/bin/sh
export NGINX_VERSION=1.15.7

wget --no-check-certificate -O ngx_vts.zip https://github.com/vozlt/nginx-module-vts/archive/master.zip && unzip ngx_vts.zip
wget --no-check-certificate -O ngx_dynamic_upstream.zip https://github.com/arkii/ngx_dynamic_upstream/archive/master.zip && unzip ngx_dynamic_upstream.zip

cp ../ngx_dynamic_upstream-master/src/ngx_inet_slab.c ngx_dynamic_upstream-master/src/ngx_inet_slab.c

wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && tar xf nginx-${NGINX_VERSION}.tar.gz && cd nginx-${NGINX_VERSION} && ./configure --add-module=../ngx_dynamic_upstream-master --add-module=../nginx-module-vts-master && make -j2
