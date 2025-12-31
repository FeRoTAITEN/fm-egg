#!/bin/ash
set -e

GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; RESET="\033[0m"
log_success(){ echo -e "${GREEN}[SUCCESS] $1${RESET}"; }
log_warning(){ echo -e "${YELLOW}[WARNING] $1${RESET}"; }
log_error(){ echo -e "${RED}[ERROR] $1${RESET}"; }

# Clean temp (لا تطيّح لو ما كان موجود)
echo "⏳ Cleaning up temporary files..."
mkdir -p /home/container/tmp
rm -rf /home/container/tmp/* || true
log_success "Temporary files removed successfully."

# Pick PHP-FPM binary
PHP_FPM="$(command -v php-fpm83 || true)"
if [ -z "$PHP_FPM" ]; then
  log_error "php-fpm83 not found in PATH."
  ls -l /usr/sbin/php-fpm* 2>/dev/null || true
  exit 1
fi

# Start PHP-FPM (Foreground أفضل داخل الكونتينر)
echo "⏳ Starting PHP-FPM..."
# إذا عندك config مخصص موجود استخدمه، وإلا شغل الافتراضي
if [ -f /home/container/php-fpm/php-fpm.conf ]; then
  "$PHP_FPM" --fpm-config /home/container/php-fpm/php-fpm.conf -F &
  log_success "PHP-FPM started with custom config."
else
  "$PHP_FPM" -F &
  log_warning "Custom PHP-FPM config not found; started with default config."
fi

# Start Nginx
echo "⏳ Starting Nginx..."
# إذا عندك config مخصص موجود استخدمه، وإلا استخدم الافتراضي اللي داخل الصورة
if [ -f /home/container/nginx/nginx.conf ]; then
  nginx -c /home/container/nginx/nginx.conf -p /home/container/ &
  log_success "Nginx started with custom config."
else
  nginx -g "daemon off;" &
  log_warning "Custom Nginx config not found; started with default /etc/nginx/nginx.conf."
fi

# (اختياري) ttyd إذا مركبه
if command -v ttyd >/dev/null 2>&1; then
  echo "⏳ Starting ttyd..."
  ttyd -p 7681 /bin/ash &
  log_success "ttyd started on :7681."
fi

log_success "All services started."

# Keep running: انتظر أي عملية تموت
wait -n
exit $?
