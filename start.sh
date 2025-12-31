#!/bin/ash
set -e

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

log_success(){ echo -e "${GREEN}[SUCCESS] $1${RESET}"; }
log_warning(){ echo -e "${YELLOW}[WARNING] $1${RESET}"; }
log_error(){ echo -e "${RED}[ERROR] $1${RESET}"; }

# ----------------------------------
# Prepare directories
# ----------------------------------
mkdir -p /home/container/tmp
mkdir -p /home/container/php-fpm
mkdir -p /home/container/nginx

echo "⏳ Cleaning temporary files..."
rm -rf /home/container/tmp/*
log_success "Temporary files removed."

# ----------------------------------
# Ensure PHP-FPM config exists
# ----------------------------------
if [ ! -f /home/container/php-fpm/php-fpm.conf ]; then
  cp /etc/php83/php-fpm.conf /home/container/php-fpm/php-fpm.conf
fi

if [ ! -f /home/container/php-fpm/www.conf ]; then
  cp /etc/php83/php-fpm.d/www.conf /home/container/php-fpm/www.conf
fi

# Fix PHP-FPM logging paths (avoid /var/log)
sed -i 's#^[; ]*error_log *=.*#error_log = /home/container/tmp/php-fpm-error.log#' /home/container/php-fpm/php-fpm.conf
sed -i 's#^[; ]*php_admin_value\[error_log\].*#php_admin_value[error_log] = /home/container/tmp/php-error.log#' /home/container/php-fpm/www.conf
sed -i 's#^[; ]*php_admin_flag\[log_errors\].*#php_admin_flag[log_errors] = on#' /home/container/php-fpm/www.conf

# ----------------------------------
# Start PHP-FPM
# ----------------------------------
PHP_FPM="$(command -v php-fpm83)"
if [ -z "$PHP_FPM" ]; then
  log_error "php-fpm83 not found!"
  exit 1
fi

echo "⏳ Starting PHP-FPM..."
"$PHP_FPM" --fpm-config /home/container/php-fpm/php-fpm.conf -F &
log_success "PHP-FPM started."

# ----------------------------------
# Start NGINX
# ----------------------------------
echo "⏳ Starting Nginx..."
if [ -f /home/container/nginx/nginx.conf ]; then
  nginx -c /home/container/nginx/nginx.conf -p /home/container/ &
else
  nginx -g "daemon off;" &
fi
log_success "Nginx started."

# ----------------------------------
# Start ttyd (WRITABLE)
# ----------------------------------
if command -v ttyd >/dev/null 2>&1; then
  echo "⏳ Starting ttyd..."
  ttyd --writable -p 7681 /bin/ash &
  log_success "ttyd started on port 7681."
fi

# ----------------------------------
# Keep container alive
# ----------------------------------
wait -n
