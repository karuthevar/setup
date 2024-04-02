#!/bin/bash -xe
yum update -y
yum install -y wget unzip
# Install and configure CloudWatch agent
rpm -U https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
cat << 'EOF' | sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
{
  "file_path": "/var/log/*",
  "log_group_name": "{instance_id}",
  "log_stream_name": "{instance_id}-var_log-log"
}
        ]
      }
    }
  }
}
EOF
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Create users for Nginx, Promtail, Loki, and Grafana
useradd -r -d /var/cache/nginx -s /sbin/nologin nginx
useradd -s /sbin/nologin promtail
useradd -s /sbin/nologin loki
useradd -s /sbin/nologin grafana
useradd -s /sbin/nologin prometheus
useradd -s /sbin/nologin node_exporter
# Needed for promtail to read files /var folder
usermod -a -G root promtail 
usermod -a -G loki promtail
usermod -a -G grafana promtail 
usermod -a -G nginx promtail
# Download and install the ADOT Collector from the specified location
rpm -ivh https://aws-otel-collector.s3.amazonaws.com/amazon_linux/amd64/latest/aws-otel-collector.rpm

# Download and run Jaeger
wget https://github.com/jaegertracing/jaeger/releases/download/v1.28.0/jaeger-1.28.0-linux-amd64.tar.gz
tar xf jaeger-1.28.0-linux-amd64.tar.gz
cd jaeger-1.28.0-linux-amd64
cp jaeger-all-in-one  /usr/local/bin

cat <<EOF > /etc/systemd/system/jaeger.service
[Unit]
Description=Jaeger All-in-One
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/jaeger-all-in-one
Restart=on-failure
  
[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start Jaeger service
systemctl daemon-reload
systemctl enable jaeger
systemctl start jaeger

# Create the ADOT Collector configuration file
cat <<EOF > /opt/aws/aws-otel-collector/etc/config.yaml
extensions:
  health_check: {}
  pprof:
    endpoint: 0.0.0.0:1777
  zpages:
    endpoint: 0.0.0.0:55679
  sigv4auth:
    region: "${Region}"

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
  prometheus:
    config:
      scrape_configs:
        - job_name: 'adot-collector'
scrape_interval: 10s
static_configs:
  - targets: ['localhost:8888']
        - job_name: 'node_exporter_via_adot'
scrape_interval: 15s
static_configs:
  - targets: ['localhost:9100']

processors:
  batch: {}
exporters:
  zipkin:
    endpoint: "http://localhost:9411"

  jaeger:
    endpoint: "http://localhost:16686"
  
  loki:
    endpoint: "http://localhost:3100"
    
  prometheusremotewrite:
    endpoint: "https://aps-workspaces.${Region}.amazonaws.com/workspaces/${AmpWorkspaceId}/api/v1/remote_write"
    auth:
      authenticator: sigv4auth

service:
  extensions: [health_check, pprof, zpages, sigv4auth]
  pipelines:
    metrics:
      receivers: [otlp, prometheus]
      processors: [batch]
      exporters: [prometheusremotewrite]
    traces:
      receivers: [otlp]
      processors: [resource]
      exporters: [logging,zipkin,jaeger,otlphttp]
    logs:
      receivers: [otlp]
      processors: [loki]      
EOF

# Enable and start the ADOT Collector
sudo systemctl enable aws-otel-collector
sudo systemctl start aws-otel-collector

 # Install and Configure Loki with S3 backend
wget https://github.com/grafana/loki/releases/download/v2.9.1/loki-linux-amd64.zip
unzip loki-linux-amd64.zip
mv loki-linux-amd64 /usr/local/bin/loki
chown loki:loki /usr/local/bin/loki
# Configure Loki specific directories
mkdir /var/loki
chown loki:loki /var/loki

cat << 'EOF' | sudo tee /etc/loki-config.yaml
auth_enabled: false
server:
  http_listen_port: 3100
ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s
  max_transfer_retries: 0
  wal:
   dir: "/var/loki/wal"

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: s3
      schema: v11
      index:
        prefix: index_loki_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /var/loki/boltdb-shipper-active
    cache_location: /var/loki/boltdb-shipper-cache
    cache_ttl: 24h# Can be adjusted
    shared_store: s3

  aws:
    s3: s3://${BucketName}  # The S3 bucket
    s3forcepathstyle: true   # Optional based on the bucket setup
    bucketnames: ${BucketName}
    region: ${Region}

compactor:
  working_directory: /var/loki/data/retention
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 150
  shared_store: s3

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h

chunk_store_config:
  max_look_back_period: 0s
EOF

cat << 'EOF' | sudo tee /etc/systemd/system/loki.service
[Unit]
Description=Loki service
After=network.target

[Service]
Type=simple
User=loki
ExecStart=/usr/local/bin/loki -config.file=/etc/loki-config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start loki
sudo systemctl enable loki


# Install NGINX
# yum install nginx -y
sudo amazon-linux-extras install -y nginx1
yum install httpd-tools -y

# Install self signed tls certifying authority and generating self signed cert.

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") 
EC2_PUBLIC_DNS_NAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/public-hostname) 
#echo $EC2_PUBLIC_DNS_NAME


CA_DIR="/etc/ssl/ca" && CERT_DIR="/etc/ssl/self-signed" && PASSPHRASE_CA=$(openssl rand -base64 32) && mkdir -p $CA_DIR && openssl genrsa -aes256 -out $CA_DIR/ca.key -passout pass:$PASSPHRASE_CA && openssl req -x509 -new -key $CA_DIR/ca.key -out $CA_DIR/ca.crt -days 365 -subj "/CN=MyCA" -passin pass:$PASSPHRASE_CA && mkdir -p $CERT_DIR && PASSPHRASE_CERT=$(openssl rand -base64 32) && openssl genrsa -aes256 -out $CERT_DIR/localhost.key -passout pass:$PASSPHRASE_CERT && openssl req -new -key $CERT_DIR/localhost.key -out $CERT_DIR/localhost.csr -subj "/CN=localhost" -passin pass:$PASSPHRASE_CERT && openssl x509 -req -in $CERT_DIR/localhost.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial -out $CERT_DIR/localhost.crt -days 365 -passin pass:$PASSPHRASE_CA && chmod 600 $CERT_DIR/localhost.key $CERT_DIR/localhost.crt

openssl rsa -in $CA_DIR/ca.key -out $CA_DIR/ca.key -passin pass:$PASSPHRASE_CA && openssl rsa -in $CERT_DIR/localhost.key -out $CERT_DIR/localhost.key -passin pass:$PASSPHRASE_CERT

openssl genrsa -aes256 -out $CERT_DIR/$EC2_PUBLIC_DNS_NAME.key -passout pass:$PASSPHRASE_CERT && openssl req -new -key $CERT_DIR/$EC2_PUBLIC_DNS_NAME.key -out $CERT_DIR/$EC2_PUBLIC_DNS_NAME.csr -subj "/CN=$EC2_PUBLIC_DNS_NAME" -passin pass:$PASSPHRASE_CERT && openssl x509 -req -in $CERT_DIR/$EC2_PUBLIC_DNS_NAME.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial -out $CERT_DIR/$EC2_PUBLIC_DNS_NAME.crt -days 365 -passin pass:$PASSPHRASE_CA && chmod 600 $CERT_DIR/$EC2_PUBLIC_DNS_NAME.key $CERT_DIR/$EC2_PUBLIC_DNS_NAME.crt

openssl rsa -in $CA_DIR/ca.key -out $CA_DIR/ca.key -passin pass:$PASSPHRASE_CA && openssl rsa -in $CERT_DIR/$EC2_PUBLIC_DNS_NAME.key -out $CERT_DIR/$EC2_PUBLIC_DNS_NAME.key -passin pass:$PASSPHRASE_CERT

# Update permissions for /etc/ssl folder for promtail access
chmod -R 755 /etc/ssl
# Setup password for the loki user
echo "${LokiPassword}" | htpasswd -i -c /etc/nginx/passwords ${LokiUsername}

# Populate NGINX configuration
cat << 'EOF' | sudo tee /etc/nginx/nginx.conf 
user nginx;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
worker_rlimit_nofile 100000;

events {
        worker_connections 4000;
        use epoll;
        multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;

    map $http_upgrade $connection_upgrade {
  default upgrade;
  '' close;
    }

    access_log off;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_min_length 10240;
    gzip_comp_level 1;
    gzip_vary on;
    gzip_disable msie6;
    gzip_proxied expired no-cache no-store private auth;
    gzip_types text/css text/javascript text/xml text/plain text/x-component application/javascript application/x-javascript application/json application/xml application/rss+xml application/atom+xml font/truetype font/opentype application/vnd.ms-fontobject image/svg+xml;

    reset_timedout_connection on;
    client_body_timeout 10;
    send_timeout 2;
    keepalive_requests 100000;

    include /etc/nginx/conf.d/*.conf;
}
EOF

# Populate Loki configuration for NGINX
cat << 'EOF' | sudo tee /etc/nginx/conf.d/loki.conf
upstream loki {
  server 127.0.0.1:3100;
  keepalive 15;
}


server {
  listen 443 ssl;
  server_name localhost;
  ssl_certificate /etc/ssl/self-signed/localhost.crt;  # Path to your certificate file
  ssl_certificate_key /etc/ssl/self-signed/localhost.key;  # Path to your private key file
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers off;

  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 8.8.8.8 8.8.4.4 valid=300s;
  resolver_timeout 5s;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

  auth_basic "loki auth";
  auth_basic_user_file /etc/nginx/passwords;

  location / {
    proxy_read_timeout 1800s;
    proxy_connect_timeout 1600s;
    proxy_pass http://loki;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Connection "Keep-Alive";
    proxy_set_header Proxy-Connection "Keep-Alive";
    proxy_redirect off;
  }

  location /ready {
    proxy_pass http://loki;
    proxy_http_version 1.1;
    proxy_set_header Connection "Keep-Alive";
    proxy_set_header Proxy-Connection "Keep-Alive";
    proxy_redirect off;
    auth_basic "off";
  }

}

EOF

chown -R nginx:nginx /etc/nginx

# Start and enable NGINX
systemctl start nginx
systemctl enable nginx

# Install Grafana and Configure Loki as Datasource
cat << 'EOF' | sudo tee /etc/yum.repos.d/grafana.repo
[grafana]
name=grafana
baseurl=https://packages.grafana.com/oss/rpm
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://packages.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF

yum install grafana -y
chown grafana:grafana /usr/sbin/grafana-server

cat << 'EOF' | sudo tee /etc/grafana/provisioning/datasources/loki-datasource.yml
apiVersion: 1
datasources:
- name: Loki_https
  type: loki
  access: proxy
  url: https://localhost
  basicAuth: true
  basicAuthUser: ${LokiUsername}
  jsonData:
    maxLines: 1000
    tlsSkipVerify: true #skip TLS verification due to the use of self signed cert. Not recommended for prod environment.
  secureJsonData:
    basicAuthPassword: ${LokiPassword} 
  version: 1
- name: Prometheus
  type: prometheus
  access: proxy
  url: http://localhost:9090
  basicAuth: false
  withCredentials: false
  isDefault: false
  jsonData:
    tlsSkipVerify: true
    timeInterval: "5s"
  editable: true
  version: 1
EOF

# Download and setup the dashboard JSON
mkdir -p /var/lib/grafana/dashboards
wget https://grafana.com/api/dashboards/1860/revisions/33/download -O /var/lib/grafana/dashboards/dashboard_1860.json
#wget https://grafana.com/api/dashboards/3662/revisions/2/download -O /var/lib/grafana/dashboards/dashboard_3662.json
# Add dashboard provisioning file
cat << 'EOF' | sudo tee /etc/grafana/provisioning/dashboards/dashboard_provider.yml
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
EOF

# Configure Grafana by generating a sample grafana.ini
sudo mv /etc/grafana/grafana.ini /etc/grafana/grafana.ini.original
cat << EOF | sudo tee /etc/grafana/grafana.ini
[server]
protocol = https
http_port = 3000
https_port = 1443
domain = $EC2_PUBLIC_DNS_NAME
root_url = %(protocol)s://%(domain)s:%(http_port)s
cert_file = $CERT_DIR/$EC2_PUBLIC_DNS_NAME.crt
cert_key = $CERT_DIR/$EC2_PUBLIC_DNS_NAME.key

[security]
admin_user = ${GrafanaUsername}
admin_password = ${GrafanaPassword}
cookie_secure = true
cookie_samesite = strict
disable_gravatar = false


[auth]
disable_login_form = false
disable_signout_menu = false
sigv4_auth_enabled = true

EOF

systemctl start grafana-server
systemctl enable grafana-server


# Install and Configure Promtail
wget https://github.com/grafana/loki/releases/download/v2.4.1/promtail-linux-amd64.zip
unzip promtail-linux-amd64.zip
mv promtail-linux-amd64 /usr/local/bin/promtail
chown promtail:promtail /usr/local/bin/promtail

cat << 'EOF' | sudo tee /etc/promtail-config.yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: https://localhost/loki/api/v1/push
    basic_auth:
      username: ${LokiUsername}
      password: ${LokiPassword}
    tls_config:
      ca_file: /etc/ssl/ca/ca.crt
      cert_file: /etc/ssl/self-signed/localhost.crt
      key_file: /etc/ssl/self-signed/localhost.key
      insecure_skip_verify: true

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
- localhost
        labels:
job: system_logs
__path__: /var/log/*.*
  - job_name: nginx
    static_configs:
      - targets:
- localhost
        labels:
job: nginx_logs
__path__: /var/log/nginx/*.log
  - job_name: grafana
    static_configs:
      - targets:
- localhost
        labels:
job: grafana_logs
__path__: /var/log/grafana/*.log*
EOF

cat << 'EOF' | sudo tee /etc/systemd/system/promtail.service
[Unit]
Description=Promtail service
After=network.target

[Service]
Type=simple
User=promtail
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail-config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Starting Promtail service
sudo systemctl daemon-reload
systemctl start promtail
systemctl enable promtail


# Install Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvfz node_exporter-1.7.0.linux-amd64.tar.gz
cp node_exporter-1.7.0.linux-amd64/node_exporter /usr/local/bin

# Create a systemd service file for Node Exporter
cat <<EOF > /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the Node Exporter service
systemctl daemon-reload
systemctl enable node_exporter
systemctl start node_exporter

# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.49.0-rc.0/prometheus-2.49.0-rc.0.linux-amd64.tar.gz
tar xvfz prometheus-2.49.0-rc.0.linux-amd64.tar.gz
cp prometheus-2.49.0-rc.0.linux-amd64/prometheus /usr/local/bin
cp prometheus-2.49.0-rc.0.linux-amd64/promtool /usr/local/bin
mkdir /etc/prometheus
mkdir /var/lib/prometheus
cp -r prometheus-*/consoles /etc/prometheus
cp -r prometheus-*/console_libraries /etc/prometheus

# Create a Prometheus configuration file
cat <<EOF > /etc/prometheus/prometheus.yml
global:
  scrape_interval:     15s
  evaluation_interval: 15s
scrape_configs:
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:9100']
  - job_name: 'loki'
    static_configs:
      - targets: ['localhost:3100']
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF

# Change ownership of the Prometheus directories
chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus

# Create a systemd service file for Prometheus
cat <<EOF > /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
--config.file=/etc/prometheus/prometheus.yml \
--storage.tsdb.path=/var/lib/prometheus/ \
--web.console.templates=/etc/prometheus/consoles \
--web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the Prometheus service
systemctl daemon-reload
systemctl enable prometheus
systemctl start prometheus
 
# Enable and start the Prometheus service
systemctl daemon-reload
systemctl enable prometheus
systemctl start prometheus