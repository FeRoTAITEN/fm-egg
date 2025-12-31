FROM alpine:3.20

# ====== Base system ======
RUN apk update && apk add --no-cache \
    bash \
    sudo \
    shadow \
    coreutils \
    procps \
    curl \
    ca-certificates \
    git \
    nano \
    vim \
    nginx \
    supervisor \
    ttyd \
    libreoffice \
    libreoffice-writer \
    libreoffice-calc \
    libreoffice-impress \
    libreoffice-common \
    libreoffice-lang-en \
    php83 \
    php83-fpm \
    php83-cli \
    php83-common \
    php83-curl \
    php83-mbstring \
    php83-json \
    php83-openssl \
    php83-pdo \
    php83-pdo_mysql \
    php83-pdo_pgsql \
    php83-pdo_sqlite \
    php83-mysqli \
    php83-xml \
    php83-zip \
    php83-gd \
    php83-bcmath \
    php83-intl \
    php83-fileinfo \
    php83-tokenizer \
    php83-session \
    php83-simplexml \
    php83-ctype \
    php83-iconv

# ====== Create container user (match Pterodactyl UID 1002) ======
RUN addgroup -g 1003 container \
 && adduser -D -u 1002 -G container -h /home/container -s /bin/bash container \
 && echo "container ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# ====== Directories ======
RUN mkdir -p /home/container \
    /home/container/webroot \
    /run/nginx \
    /var/log/nginx \
    /var/log/php83 \
 && chown -R container:container /home/container

# ====== PHP-FPM ======
RUN sed -i 's/^user = .*/user = container/' /etc/php83/php-fpm.d/www.conf \
 && sed -i 's/^group = .*/group = container/' /etc/php83/php-fpm.d/www.conf \
 && sed -i 's/^listen = .*/listen = 127.0.0.1:9000/' /etc/php83/php-fpm.d/www.conf

# ====== Nginx config ======
RUN printf '%s\n' \
"user container;" \
"worker_processes auto;" \
"events { worker_connections 1024; }" \
"http {" \
"  include       mime.types;" \
"  default_type  application/octet-stream;" \
"  sendfile on;" \
"  keepalive_timeout 65;" \
"  server {" \
"    listen 8080;" \
"    root /home/container/webroot;" \
"    index index.php index.html;" \
"    location / {" \
"      try_files \$uri \$uri/ /index.php?\$query_string;" \
"    }" \
"    location ~ \\.php\$ {" \
"      fastcgi_pass 127.0.0.1:9000;" \
"      include fastcgi.conf;" \
"    }" \
"  }" \
"}" > /etc/nginx/nginx.conf

# ====== Supervisor ======
RUN printf '%s\n' \
"[supervisord]" \
"nodaemon=true" \
"" \
"[program:php-fpm]" \
"command=/usr/sbin/php-fpm83 -F" \
"autostart=true" \
"autorestart=true" \
"" \
"[program:nginx]" \
"command=/usr/sbin/nginx -g 'daemon off;'" \
"autostart=true" \
"autorestart=true" \
"" \
"[program:terminal]" \
"command=/usr/bin/ttyd -p 7681 bash" \
"autostart=true" \
"autorestart=true" \
> /etc/supervisord.conf

# ====== Permissions ======
RUN chown -R container:container /home/container \
 && chmod +x /usr/bin/ttyd

# ====== Runtime ======
USER container
WORKDIR /home/container

EXPOSE 8080 7681

CMD ["/usr/bin/supervisord","-c","/etc/supervisord.conf"]
