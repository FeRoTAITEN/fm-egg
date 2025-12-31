FROM alpine:3.20

# ====== Base system & PHP 8.3 ======
# ملاحظة: تم حذف php83-json لأنها مدمجة تلقائياً
RUN apk update && apk add --no-cache \
    bash sudo shadow coreutils procps curl ca-certificates git nano vim nginx supervisor ttyd \
    libreoffice libreoffice-writer libreoffice-calc libreoffice-impress libreoffice-common libreoffice-lang-en \
    php83 php83-fpm php83-cli php83-common php83-curl php83-mbstring php83-openssl \
    php83-pdo php83-pdo_mysql php83-pdo_pgsql php83-pdo_sqlite php83-mysqli \
    php83-xml php83-zip php83-gd php83-bcmath php83-intl php83-fileinfo \
    php83-tokenizer php83-session php83-simplexml php83-ctype php83-iconv

# ====== Create container user (Pterodactyl UID 1002) ======
RUN addgroup -g 1003 container \
 && adduser -D -u 1002 -G container -h /home/container -s /bin/bash container \
 && echo "container ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# ====== Directories & Permissions ======
RUN mkdir -p /home/container/webroot /run/nginx /var/log/nginx /var/log/php83 /var/lib/nginx \
 && chown -R container:container /home/container /run/nginx /var/log/nginx /var/log/php83 /var/lib/nginx

# ====== PHP-FPM Config ======
RUN sed -i 's/^user = .*/user = container/' /etc/php83/php-fpm.d/www.conf \
 && sed -i 's/^group = .*/group = container/' /etc/php83/php-fpm.d/www.conf \
 && sed -i 's/^listen = .*/listen = 127.0.0.1:9000/' /etc/php83/php-fpm.d/www.conf

# ====== Nginx config ======
RUN printf 'user container;\nworker_processes auto;\nevents { worker_connections 1024; }\nhttp {\n  include mime.types;\n  sendfile on;\n  server {\n    listen 8080;\n    root /home/container/webroot;\n    index index.php index.html;\n    location / {\n      try_files $uri $uri/ /index.php?$query_string;\n    }\n    location ~ \.php$ {\n      fastcgi_pass 127.0.0.1:9000;\n      include fastcgi.conf;\n    }\n  }\n}' > /etc/nginx/nginx.conf

# ====== Supervisor config ======
RUN printf '[supervisord]\nnodaemon=true\n\n[program:php-fpm]\ncommand=/usr/sbin/php-fpm83 -F\nautostart=true\nautorestart=true\n\n[program:nginx]\ncommand=/usr/sbin/nginx -g "daemon off;"\nautostart=true\nautorestart=true\n\n[program:terminal]\ncommand=/usr/bin/ttyd -p 7681 bash\nautostart=true\nautorestart=true' > /etc/supervisord.conf

# ====== Runtime ======
USER container
WORKDIR /home/container
EXPOSE 8080 7681

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
