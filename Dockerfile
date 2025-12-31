FROM alpine:3.20

# ====== Base system & PHP 8.3 ======
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

# ====== User Setup ======
RUN addgroup -g 1003 container \
 && adduser -D -u 1002 -G container -h /home/container -s /bin/bash container \
 && echo "container ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# ====== Directories & Permissions ======
RUN mkdir -p /home/container/webroot /run/nginx /var/log/nginx /var/log/php83 \
 && chown -R container:container /home/container /run/nginx /var/log/nginx /var/log/php83

# ====== Configurations ======
# (نفس إعدادات sed و printf التي وضعتها أنت صحيحة تماماً)
RUN sed -i 's/^user = .*/user = container/' /etc/php83/php-fpm.d/www.conf \
 && sed -i 's/^group = .*/group = container/' /etc/php83/php-fpm.d/www.conf \
 && sed -i 's/^listen = .*/listen = 127.0.0.1:9000/' /etc/php83/php-fpm.d/www.conf

# ... بقية ملفك (Nginx & Supervisor) كما هي ...
