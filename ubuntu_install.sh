#!/usr/bin/env bash

# set parameters for installation

export ${WORDPRESS_DB_PASSWORD}="" 

export ${WORDPRESS_ADMIN_USER}=""

export ${WORDPRESS_ADMIN_PASSWORD}=""

export ${WORDPRESS_ADMIN_EMAIL}=""

export ${WORDPRESS_URL}=""

export ${WORDPRESS_SITE_TITLE}=""



if [ "$EUID" -ne 0 ];then
  >&2 echo "This script requires root level access to run"
  exit 1
fi

if [ -z "${WORDPRESS_DB_PASSWORD}" ]; then
  >&2 echo "WORDPRESS_DB_PASSWORD must be set"
  >&2 echo "Here is a random one that you can paste:"
  >&2 echo "export WORDPRESS_DB_PASSWORD=\"$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)\""
  exit 1
fi

if [ -z "${WORDPRESS_ADMIN_USER}" ]; then
  >&2 echo "WORDPRESS_ADMIN_USER must be set"
  >&2 echo "Here is a sensible default that you can paste:"
  >&2 echo "export WORDPRESS_ADMIN_USER=\"moderator\""
  exit 1
fi

if [ -z "${WORDPRESS_ADMIN_PASSWORD}" ]; then
  >&2 echo "WORDPRESS_ADMIN_PASSWORD must be set"
  >&2 echo "Here is a random one that you can paste:"
  >&2 echo "export WORDPRESS_ADMIN_PASSWORD=\"$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)\""
  exit 1
fi

if [ -z "${WORDPRESS_ADMIN_EMAIL}" ]; then
  >&2 echo "WORDPRESS_ADMIN_EMAIL must be set"
  exit 1
fi

if [ -z "${WORDPRESS_URL}" ]; then
  >&2 echo "WORDPRESS_URL must be set"
  exit 1
fi

if [ -z "${WORDPRESS_SITE_TITLE}" ]; then
  >&2 echo "WORDPRESS_SITE_TITLE must be set"
  exit 1
fi

# Best practice settings for running bash scripts:

# Exit the script when an error is encountered
set -o errexit
# Exit the script when a pipe operation fails
set -o pipefail
# Exit the script when there are undeclared variables
set -o nounset
# Uncomment this to see a log to the screen of each command run in the script
# set -o xtrace

export DEBIAN_FRONTEND="noninteractive"
export WORDPRESS_CLI_VERSION="2.4.0"
export WORDPRESS_CLI_MD5="dedd5a662b80cda66e9e25d44c23b25c"
export UPLOAD_MAX_FILESIZE="16M"
export TLS_HOSTNAME="$(echo ${WORDPRESS_URL} | cut -d'/' -f3)"
export NGINX_CONF_DIR="/etc/nginx"
export CERT_DIR="/etc/letsencrypt/live/${TLS_HOSTNAME}"

# Change the hostname to be the same as the WordPress hostname
if [ ! "$(hostname)" == "${TLS_HOSTNAME}" ]; then
  echo "▶ Changing hostname to ${TLS_HOSTNAME}"
  hostnamectl set-hostname "${TLS_HOSTNAME}"
fi

# Add the hostname to /etc/hosts
if [ "$(grep -m1 "${TLS_HOSTNAME}" /etc/hosts)" = "" ]; then
  echo "▶ Adding hostname ${TLS_HOSTNAME} to /etc/hosts so that WordPress can ping itself"
  printf "::1 %s\n127.0.0.1 %s\n" "${TLS_HOSTNAME}" "${TLS_HOSTNAME}" >> /etc/hosts
fi

# Make sure tools needed for install are present
echo "▶ Installing prerequisite tools"
apt-get -qq update
apt-get -qq install -y \
  bc \
  ca-certificates \
  coreutils \
  curl \
  gnupg2 \
  lsb-release

# Install the NGINX Unit repository
if [ ! -f /etc/apt/sources.list.d/unit.list ]; then
  echo "▶ Installing NGINX Unit repository"
  curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
  echo "deb https://packages.nginx.org/unit/ubuntu/ $(lsb_release -cs) unit" > /etc/apt/sources.list.d/unit.list
fi

# Install the NGINX repository
if [ ! -f /etc/apt/sources.list.d/nginx.list ]; then
  echo "▶ Installing NGINX repository"
  curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
  echo "deb https://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
fi

echo "▶ Updating repository metadata"
apt-get -qq update

# WordPress module recommendation: https://make.wordpress.org/hosting/handbook/handbook/server-environment/#php-extensions

# Ubuntu bundles the following PHP extensions with its package distribution:
# date filter hash libxml openssl pcntl pcre Reflection session sodium SPL
# standard zlib

# The php-common package contains the following extensions: exif

# Install PHP with dependencies and NGINX Unit
echo "▶ Installing PHP, NGINX Unit, NGINX, Certbot, and MariaDB"
apt-get -qq install -y --no-install-recommends \
  certbot \
  python3-certbot-nginx \
  php-cli \
  php-common \
  php-bcmath \
  php-curl \
  php-gd \
  php-imagick \
  php-mbstring \
  php-mysql \
  php-opcache \
  php-xml \
  php-zip \
  ghostscript \
  nginx \
  unit \
  unit-php \
  mariadb-server

# Find the major and minor PHP version so that we can write to its conf.d directory
PHP_MAJOR_MINOR_VERSION="$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)"

if [ ! -f "/etc/php/${PHP_MAJOR_MINOR_VERSION}/embed/conf.d/30-wordpress-overrides.ini" ]; then
  echo "▶ Configuring PHP for use with NGINX Unit and WordPress"
  # Add PHP configuration overrides
  cat > "/etc/php/${PHP_MAJOR_MINOR_VERSION}/embed/conf.d/30-wordpress-overrides.ini" << EOM
; Set a larger maximum upload size so that WordPress can handle
; bigger media files.
upload_max_filesize=${UPLOAD_MAX_FILESIZE}
post_max_size=${UPLOAD_MAX_FILESIZE}
; Write error log to STDERR so that error messages show up in the NGINX Unit log
error_log=/dev/stderr
EOM
fi

# Restart NGINX Unit because we have reconfigured PHP
echo "▶ Restarting NGINX Unit"
service unit restart

# Set up the WordPress database
echo "▶ Configuring MariaDB for WordPress"
mysqladmin create wordpress || echo "Ignoring above error because database may already exist"
mysql -e "GRANT ALL PRIVILEGES ON wordpress.* TO \"wordpress\"@\"localhost\" IDENTIFIED BY \"$WORDPRESS_DB_PASSWORD\"; FLUSH PRIVILEGES;"

if [ ! -f /usr/local/bin/wp ]; then
  # Install the WordPress CLI
  echo "▶ Installing the WordPress CLI tool"
  curl --retry 6 -Ls "https://github.com/wp-cli/wp-cli/releases/download/v${WORDPRESS_CLI_VERSION}/wp-cli-${WORDPRESS_CLI_VERSION}.phar" > /usr/local/bin/wp
  echo "$WORDPRESS_CLI_MD5 /usr/local/bin/wp" | md5sum -c -
  chmod +x /usr/local/bin/wp
fi

if [ ! -d /var/www/wordpress ]; then
  # Create WordPress directories
  mkdir -p /var/www/wordpress
  chown -R www-data:www-data /var/www

  # Download WordPress using the WordPress CLI
  echo "▶ Installing WordPress"
  su -s /bin/sh -c 'wp --path=/var/www/wordpress core download' www-data

  WP_CONFIG_CREATE_CMD="wp --path=/var/www/wordpress config create --extra-php --dbname=wordpress --dbuser=wordpress --dbhost=\"localhost:/var/run/mysqld/mysqld.sock\" --dbpass=\"${WORDPRESS_DB_PASSWORD}\""

  # This snippet is injected into the wp-config.php file when it is created;
  # it informs WordPress that we are behind a reverse proxy and as such
  # allows it to generate links using HTTPS
  cat > /tmp/wp_forwarded_for.php << 'EOM'
/* Turn HTTPS 'on' if HTTP_X_FORWARDED_PROTO matches 'https' */
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strpos($_SERVER['HTTP_X_FORWARDED_PROTO'], 'https') !== false) {
    $_SERVER['HTTPS'] = 'on';
}

if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $_SERVER['HTTP_HOST'] = $_SERVER['HTTP_X_FORWARDED_HOST'];
}
EOM

  # Create WordPress configuration
  su -s /bin/sh -p -c "cat /tmp/wp_forwarded_for.php | ${WP_CONFIG_CREATE_CMD}" www-data
  rm /tmp/wp_forwarded_for.php
  su -s /bin/sh -p -c "wp --path=/var/www/wordpress config set 'FORCE_SSL_ADMIN' 'true'" www-data

  # Install WordPress
  WP_SITE_INSTALL_CMD="wp --path=/var/www/wordpress core install --url=\"${WORDPRESS_URL}\" --title=\"${WORDPRESS_SITE_TITLE}\" --admin_user=\"${WORDPRESS_ADMIN_USER}\" --admin_password=\"${WORDPRESS_ADMIN_PASSWORD}\" --admin_email=\"${WORDPRESS_ADMIN_EMAIL}\" --skip-email"
  su -s /bin/sh -p -c "${WP_SITE_INSTALL_CMD}" www-data

  # Set permalink structure to a sensible default that isn't in the UI
  su -s /bin/sh -p -c "wp --path=/var/www/wordpress option update permalink_structure '/%year%/%monthnum%/%postname%/'" www-data

  # Remove sample file because it is cruft and could be a security problem
  rm /var/www/wordpress/wp-config-sample.php

  # Ensure that WordPress permissions are correct
  find /var/www/wordpress -type d -exec chmod g+s {} \;
  chmod g+w /var/www/wordpress/wp-content
  chmod -R g+w /var/www/wordpress/wp-content/themes
  chmod -R g+w /var/www/wordpress/wp-content/plugins
fi

if [ "${container:-unknown}" != "lxc" ] && [ "$(grep -m1 -a container=lxc /proc/1/environ | tr -d '\0')" == "" ]; then
  NAMESPACES='"namespaces": {
        "cgroup": true,
        "credential": true,
        "mount": true,
        "network": false,
        "pid": true,
        "uname": true
    }'
else
  NAMESPACES='"namespaces": {}'
fi

PHP_MEM_LIMIT="$(grep 'memory_limit' /etc/php/7.4/embed/php.ini | tr -d ' ' | cut -f2 -d= | numfmt --from=iec)"
AVAIL_MEM="$(grep MemAvailable /proc/meminfo | tr -d ' kB' | cut -f2 -d: | numfmt --from-unit=K)"
MAX_PHP_PROCESSES="$(echo "${AVAIL_MEM}/${PHP_MEM_LIMIT}+5" | bc)"
echo "▶ Calculated the maximum number of PHP processes as ${MAX_PHP_PROCESSES}. You may want to tune this value due to variations in your configuration. It is not unusual to see values between 10-100 in production configurations."

echo "▶ Configuring NGINX Unit to use PHP and WordPress"
cat > /tmp/wordpress.json << EOM
{
  "settings": {
    "http": {
      "header_read_timeout": 30,
      "body_read_timeout": 30,
      "send_timeout": 30,
      "idle_timeout": 180,
      "max_body_size": $(numfmt --from=iec ${UPLOAD_MAX_FILESIZE})
    }
  },
  "listeners": {
    "127.0.0.1:8080": {
      "pass": "routes/wordpress"
    }
  },
  "routes": {
    "wordpress": [
      {
        "match": {
          "uri": [
            "*.php",
            "*.php/*",
            "/wp-admin/"
          ]
        },
        "action": {
          "pass": "applications/wordpress/direct"
        }
      },
      {
        "action": {
          "share": "/var/www/wordpress",
          "fallback": {
            "pass": "applications/wordpress/index"
          }
        }
      }
    ]
  },
  "applications": {
    "wordpress": {
      "type": "php",
      "user": "www-data",
      "group": "www-data",
      "processes": {
        "max": ${MAX_PHP_PROCESSES},
        "spare": 1
      },
      "isolation": {
        ${NAMESPACES}
      },
      "targets": {
        "direct": {
          "root": "/var/www/wordpress/"
        },
        "index": {
          "root": "/var/www/wordpress/",
          "script": "index.php"
        }
      }
    }
  }
}
EOM

curl -X PUT --data-binary @/tmp/wordpress.json --unix-socket /run/control.unit.sock http://localhost/config

# Make directory for NGINX cache
mkdir -p /var/cache/nginx/proxy

echo "▶ Configuring NGINX"
cat > ${NGINX_CONF_DIR}/nginx.conf << EOM
user nginx;
worker_processes auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       ${NGINX_CONF_DIR}/mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    sendfile        on;
    client_max_body_size ${UPLOAD_MAX_FILESIZE};
    keepalive_timeout  65;

    # gzip settings
    include ${NGINX_CONF_DIR}/gzip_compression.conf;

    # Cache settings
    proxy_cache_path /var/cache/nginx/proxy
        levels=1:2
        keys_zone=wp_cache:10m
        max_size=10g
        inactive=60m
        use_temp_path=off;

    include ${NGINX_CONF_DIR}/conf.d/*.conf;
}
EOM

cat > ${NGINX_CONF_DIR}/gzip_compression.conf << 'EOM'
# Credit: https://github.com/h5bp/server-configs-nginx/

# ----------------------------------------------------------------------
# | Compression                                                        |
# ----------------------------------------------------------------------

# https://nginx.org/en/docs/http/ngx_http_gzip_module.html

# Enable gzip compression.
# Default: off
gzip on;

# Compression level (1-9).
# 5 is a perfect compromise between size and CPU usage, offering about 75%
# reduction for most ASCII files (almost identical to level 9).
# Default: 1
gzip_comp_level 6;

# Don't compress anything that's already small and unlikely to shrink much if at
# all (the default is 20 bytes, which is bad as that usually leads to larger
# files after gzipping).
# Default: 20
gzip_min_length 256;

# Compress data even for clients that are connecting to us via proxies,
# identified by the "Via" header (required for CloudFront).
# Default: off
gzip_proxied any;

# Tell proxies to cache both the gzipped and regular version of a resource
# whenever the client's Accept-Encoding capabilities header varies;
# Avoids the issue where a non-gzip capable client (which is extremely rare
# today) would display gibberish if their proxy gave them the gzipped version.
# Default: off
gzip_vary on;

# Compress all output labeled with one of the following MIME-types.
# `text/html` is always compressed by gzip module.
# Default: text/html
gzip_types
  application/atom+xml
  application/geo+json
  application/javascript
  application/x-javascript
  application/json
  application/ld+json
  application/manifest+json
  application/rdf+xml
  application/rss+xml
  application/vnd.ms-fontobject
  application/wasm
  application/x-web-app-manifest+json
  application/xhtml+xml
  application/xml
  font/eot
  font/otf
  font/ttf
  image/bmp
  image/svg+xml
  text/cache-manifest
  text/calendar
  text/css
  text/javascript
  text/markdown
  text/plain
  text/xml
  text/vcard
  text/vnd.rim.location.xloc
  text/vtt
  text/x-component
  text/x-cross-domain-policy;
EOM

cat > ${NGINX_CONF_DIR}/conf.d/default.conf << EOM
upstream unit_php_upstream {
    server 127.0.0.1:8080;

    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;

    # ACME-challenge used by Certbot for Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
      root /var/www/certbot;
    }

    location / {
      return 301 https://${TLS_HOSTNAME}\$request_uri;
    }
}

server {
    listen      443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${TLS_HOSTNAME};
    root        /var/www/wordpress/;

    # Let's Encrypt configuration
    ssl_certificate         ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key     ${CERT_DIR}/privkey.pem;
    ssl_trusted_certificate ${CERT_DIR}/chain.pem;

    include ${NGINX_CONF_DIR}/options-ssl-nginx.conf;
    ssl_dhparam ${NGINX_CONF_DIR}/ssl-dhparams.pem;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # Proxy caching
    proxy_cache wp_cache;
    proxy_cache_valid 200 302 1h;
    proxy_cache_valid 404 1m;
    proxy_cache_revalidate on;
    proxy_cache_background_update on;
    proxy_cache_lock on;
    proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
    
    # Deny all attempts to access hidden files such as .htaccess, .htpasswd, 
    # .DS_Store (Mac)
    # Keep logging the requests to parse later (or to pass to firewall utilities 
    # such as fail2ban)
    location ~ /\. {
        deny all;
    }

    # Deny access to any files with a .php extension in the uploads directory;
    # works in subdirectory installs and also in multi-site network.
    # Keep logging the requests to parse later (or to pass to firewall utilities 
    # such as fail2ban).
    location ~* /(?:uploads|files)/.*\.php\$ {
        deny all;
    }

    # WordPress: deny access to wp-content, wp-includes PHP files
    location ~* ^/(?:wp-content|wp-includes)/.*\.php\$ {
        deny all;
    }

    # Deny public access to wp-config.php
    location ~* wp-config.php {
        deny all;
    }

    # Do not log access for static assets, media
    location ~* \.(?:css(\.map)?|js(\.map)?|jpe?g|png|gif|ico|cur|heic|webp|tiff?|mp3|m4a|aac|ogg|midi?|wav|mp4|mov|webm|mpe?g|avi|ogv|flv|wmv)$ {
        access_log off;
    }

    location ~* \.(?:svgz?|ttf|ttc|otf|eot|woff2?)$ {
        add_header Access-Control-Allow-Origin "*";
        access_log off;
    }

    location / {
        try_files \$uri @index_php;
    }

    location @index_php {
        proxy_socket_keepalive on;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;

        proxy_pass       http://unit_php_upstream;
    }

    location ~* \.php\$ {
        proxy_socket_keepalive on;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;

        try_files        \$uri =404;
        proxy_pass       http://unit_php_upstream;
    }
}
EOM

echo "▶ Stopping NGINX in order to set up Let's Encrypt"
service nginx stop

mkdir -p /var/www/certbot
chown www-data:www-data /var/www/certbot
chmod g+s /var/www/certbot

if [ ! -f ${NGINX_CONF_DIR}/options-ssl-nginx.conf ]; then
  echo "▶ Downloading recommended TLS parameters"
  curl --retry 6 -Ls -z "Tue, 14 Apr 2020 16:36:07 GMT" \
    -o "${NGINX_CONF_DIR}/options-ssl-nginx.conf" \
    "https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf" \
    || echo "Couldn't download latest options-ssl-nginx.conf"
fi

if [ ! -f ${NGINX_CONF_DIR}/ssl-dhparams.pem ]; then
  echo "▶ Downloading recommended TLS DH parameters"
  curl --retry 6 -Ls -z "Tue, 14 Apr 2020 16:49:18 GMT" \
    -o "${NGINX_CONF_DIR}/ssl-dhparams.pem" \
    "https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem" \
    || echo "Couldn't download latest ssl-dhparams.pem"
fi

# If tls_certs_init.sh hasn't been run before, remove the self-signed certs
if [ ! -d "/etc/letsencrypt/accounts" ]; then
  echo "▶ Removing self-signed certificates"
  rm -rf "${CERT_DIR}"
fi

if [ "" = "${LETS_ENCRYPT_STAGING:-}" ] || [ "0" = "${LETS_ENCRYPT_STAGING}" ]; then
  CERTBOT_STAGING_FLAG=""
else
  CERTBOT_STAGING_FLAG="--staging"
fi

if [ ! -f "${CERT_DIR}/fullchain.pem" ]; then
  echo "▶ Generating certificates with Let's Encrypt"
  certbot certonly --standalone \
         -m "${WORDPRESS_ADMIN_EMAIL}" \
         ${CERTBOT_STAGING_FLAG} \
         --agree-tos --force-renewal --non-interactive \
         -d "${TLS_HOSTNAME}"
fi

echo "▶ Starting NGINX in order to use new configuration"
service nginx start

# Write crontab for periodic Let's Encrypt cert renewal
if [ "$(crontab -l | grep -m1 'certbot renew')" == "" ]; then
  echo "▶ Adding certbot to crontab for automatic Let's Encrypt renewal"
  (crontab -l 2>/dev/null; echo "24 3 * * * certbot renew --nginx --post-hook 'service nginx reload'") | crontab -
fi