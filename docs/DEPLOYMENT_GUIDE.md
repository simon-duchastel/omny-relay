# Deployment Guide

This guide covers production deployment of the NFC Transit Card Relay System with security hardening, monitoring, and operational best practices.

## Pre-Deployment Checklist

### Security Requirements

- [ ] **TLS Certificates**: Valid certificates from trusted CA
- [ ] **Access Control**: Network firewalls and access restrictions
- [ ] **Data Protection**: Encryption at rest and in transit
- [ ] **Audit Logging**: Comprehensive security event logging
- [ ] **Backup Strategy**: Secure backup and recovery procedures
- [ ] **Incident Response**: Security incident response plan

### Infrastructure Requirements

- [ ] **Server Capacity**: Adequate CPU, memory, and storage
- [ ] **Network Connectivity**: Reliable internet connection
- [ ] **Monitoring**: System and application monitoring setup
- [ ] **High Availability**: Redundancy for critical components
- [ ] **Disaster Recovery**: Backup site and recovery procedures

### Compliance Requirements

- [ ] **Legal Review**: Compliance with local regulations
- [ ] **Privacy Policy**: Data handling and privacy procedures
- [ ] **Terms of Service**: User agreement and liability
- [ ] **Data Retention**: Retention policies and procedures
- [ ] **Audit Trail**: Comprehensive audit logging

## Deployment Options

### Option 1: Single Server Deployment

**Recommended for**: Research labs, small teams, development

```bash
# Server requirements
CPU: 4+ cores
RAM: 8+ GB
Storage: 100+ GB SSD
Network: 100+ Mbps
OS: Ubuntu 20.04 LTS or CentOS 8
```

**Deployment Steps:**

1. **Server Setup**
   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y
   
   # Install Python 3.8+
   sudo apt install python3.8 python3.8-venv python3.8-dev
   
   # Install system dependencies
   sudo apt install build-essential libssl-dev libffi-dev
   ```

2. **Application Deployment**
   ```bash
   # Create application user
   sudo useradd -m -s /bin/bash nfcrelay
   sudo su - nfcrelay
   
   # Clone repository
   git clone <repository-url> nfc-relay
   cd nfc-relay
   
   # Setup environment
   python3 setup_environment.py
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Security Configuration**
   ```bash
   # Apply security hardening
   python server/config.py --harden
   
   # Generate production certificates
   python -c "from src.utils.crypto import TLSManager; TLSManager().generate_self_signed_cert('your-domain.com')"
   ```

4. **Service Configuration**
   ```bash
   # Create systemd service
   sudo cp deployment/nfc-relay.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable nfc-relay
   sudo systemctl start nfc-relay
   ```

### Option 2: Docker Deployment

**Recommended for**: Consistent environments, easy scaling

1. **Docker Setup**
   ```bash
   # Install Docker
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   
   # Install Docker Compose
   sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

2. **Application Deployment**
   ```bash
   # Clone and configure
   git clone <repository-url> nfc-relay
   cd nfc-relay
   
   # Configure environment
   cp .env.example .env
   # Edit .env with your settings
   
   # Deploy with Docker Compose
   docker-compose up -d
   ```

3. **Production Configuration**
   ```yaml
   # docker-compose.prod.yml
   version: '3.8'
   services:
     nfc-relay:
       image: nfc-relay:latest
       restart: unless-stopped
       ports:
         - "443:8080"
       volumes:
         - ./certs:/app/certs:ro
         - ./data:/app/data
         - ./logs:/app/logs
       environment:
         - NFC_HOST=0.0.0.0
         - NFC_PORT=8080
         - NFC_TLS=true
         - NFC_CERT_FILE=/app/certs/server.crt
         - NFC_KEY_FILE=/app/certs/server.key
       healthcheck:
         test: ["CMD", "curl", "-f", "https://localhost:8080/health"]
         interval: 30s
         timeout: 10s
         retries: 3
   ```

### Option 3: Kubernetes Deployment

**Recommended for**: Large-scale deployments, high availability

1. **Kubernetes Manifests**
   ```yaml
   # k8s/deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: nfc-relay
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: nfc-relay
     template:
       metadata:
         labels:
           app: nfc-relay
       spec:
         containers:
         - name: nfc-relay
           image: nfc-relay:latest
           ports:
           - containerPort: 8080
           env:
           - name: NFC_HOST
             value: "0.0.0.0"
           - name: NFC_PORT
             value: "8080"
           volumeMounts:
           - name: certs
             mountPath: /app/certs
             readOnly: true
           - name: data
             mountPath: /app/data
         volumes:
         - name: certs
           secret:
             secretName: nfc-relay-tls
         - name: data
           persistentVolumeClaim:
             claimName: nfc-relay-data
   ```

2. **Service and Ingress**
   ```yaml
   # k8s/service.yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: nfc-relay-service
   spec:
     selector:
       app: nfc-relay
     ports:
     - port: 8080
       targetPort: 8080
     type: ClusterIP
   
   ---
   # k8s/ingress.yaml
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: nfc-relay-ingress
     annotations:
       nginx.ingress.kubernetes.io/ssl-redirect: "true"
       nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
   spec:
     tls:
     - hosts:
       - nfc-relay.yourdomain.com
       secretName: nfc-relay-tls
     rules:
     - host: nfc-relay.yourdomain.com
       http:
         paths:
         - path: /
           pathType: Prefix
           backend:
             service:
               name: nfc-relay-service
               port:
                 number: 8080
   ```

## Security Hardening

### Network Security

1. **Firewall Configuration**
   ```bash
   # UFW (Ubuntu)
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow ssh
   sudo ufw allow 8080/tcp
   sudo ufw enable
   
   # iptables (alternative)
   sudo iptables -P INPUT DROP
   sudo iptables -P FORWARD DROP
   sudo iptables -P OUTPUT ACCEPT
   sudo iptables -A INPUT -i lo -j ACCEPT
   sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
   ```

2. **TLS Configuration**
   ```python
   # Enhanced TLS settings
   security:
     tls_version: "1.3"
     cipher_suites:
       - "TLS_AES_256_GCM_SHA384"
       - "TLS_CHACHA20_POLY1305_SHA256"
       - "TLS_AES_128_GCM_SHA256"
     perfect_forward_secrecy: true
     certificate_transparency: true
   ```

3. **Access Control**
   ```yaml
   # IP-based restrictions
   server:
     allowed_ips:
       - "192.168.1.0/24"  # Local network
       - "10.0.0.0/8"      # VPN network
     blocked_countries:
       - "CN"
       - "RU"
     rate_limiting:
       requests_per_minute: 60
       burst_size: 10
   ```

### Application Security

1. **Authentication**
   ```python
   # Client certificate authentication
   security:
     require_client_cert: true
     client_ca_file: "certs/client-ca.crt"
     cert_verification_mode: "strict"
   ```

2. **Data Protection**
   ```python
   # Enhanced encryption
   encryption:
     algorithm: "AES-256-GCM"
     key_derivation: "PBKDF2"
     key_iterations: 100000
     salt_length: 32
   ```

3. **Audit Logging**
   ```python
   # Security event logging
   audit:
     log_level: "DEBUG"
     log_authentication: true
     log_authorization: true
     log_data_access: true
     log_configuration_changes: true
     retention_days: 90
   ```

### System Security

1. **User Security**
   ```bash
   # Disable root login
   sudo passwd -l root
   
   # Configure sudo
   echo "nfcrelay ALL=(ALL) NOPASSWD:/usr/bin/systemctl restart nfc-relay" | sudo tee /etc/sudoers.d/nfcrelay
   
   # Set up SSH keys
   ssh-keygen -t ed25519 -f ~/.ssh/nfc-relay-key
   # Copy public key to server
   ```

2. **File Permissions**
   ```bash
   # Secure file permissions
   chmod 700 /opt/nfc-relay/secure_data
   chmod 600 /opt/nfc-relay/certs/*.key
   chmod 644 /opt/nfc-relay/certs/*.crt
   chmod 600 /opt/nfc-relay/config.yaml
   ```

3. **System Updates**
   ```bash
   # Automatic security updates
   sudo apt install unattended-upgrades
   sudo dpkg-reconfigure -plow unattended-upgrades
   
   # Configure automatic updates
   echo 'Unattended-Upgrade::Automatic-Reboot "false";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
   ```

## Monitoring and Alerting

### System Monitoring

1. **Prometheus Configuration**
   ```yaml
   # prometheus.yml
   global:
     scrape_interval: 15s
   
   scrape_configs:
   - job_name: 'nfc-relay'
     static_configs:
     - targets: ['localhost:8080']
     metrics_path: '/metrics'
     scrape_interval: 5s
   ```

2. **Grafana Dashboard**
   ```json
   {
     "dashboard": {
       "title": "NFC Relay Monitoring",
       "panels": [
         {
           "title": "Active Sessions",
           "type": "stat",
           "targets": [
             {
               "expr": "nfc_relay_active_sessions"
             }
           ]
         },
         {
           "title": "Packet Processing Rate",
           "type": "graph",
           "targets": [
             {
               "expr": "rate(nfc_relay_packets_processed_total[5m])"
             }
           ]
         }
       ]
     }
   }
   ```

### Application Monitoring

1. **Health Checks**
   ```python
   # health_check.py
   import asyncio
   import aiohttp
   import logging
   
   async def check_health():
       async with aiohttp.ClientSession() as session:
           try:
               async with session.get('https://localhost:8080/health') as resp:
                   if resp.status == 200:
                       health_data = await resp.json()
                       return health_data['status'] == 'healthy'
           except Exception as e:
               logging.error(f"Health check failed: {e}")
               return False
       return False
   ```

2. **Custom Metrics**
   ```python
   # metrics.py
   from prometheus_client import Counter, Histogram, Gauge
   
   # Define metrics
   session_counter = Counter('nfc_sessions_total', 'Total number of sessions')
   packet_histogram = Histogram('nfc_packet_processing_seconds', 'Packet processing time')
   active_sessions = Gauge('nfc_active_sessions', 'Number of active sessions')
   ```

### Log Management

1. **Centralized Logging**
   ```yaml
   # docker-compose.logging.yml
   version: '3.8'
   services:
     nfc-relay:
       logging:
         driver: "fluentd"
         options:
           fluentd-address: "localhost:24224"
           tag: "nfc-relay"
   
     fluentd:
       image: fluent/fluentd:v1.14
       volumes:
         - ./fluentd/conf:/fluentd/etc
         - ./logs:/var/log/fluentd
       ports:
         - "24224:24224"
   ```

2. **Log Analysis**
   ```bash
   # ELK Stack configuration
   # Elasticsearch, Logstash, Kibana setup
   docker-compose -f docker-compose.elk.yml up -d
   ```

### Alerting

1. **Alertmanager Configuration**
   ```yaml
   # alertmanager.yml
   global:
     smtp_smarthost: 'localhost:587'
     smtp_from: 'alerts@yourdomain.com'
   
   route:
     group_by: ['alertname']
     group_wait: 10s
     group_interval: 10s
     repeat_interval: 1h
     receiver: 'web.hook'
   
   receivers:
   - name: 'web.hook'
     email_configs:
     - to: 'admin@yourdomain.com'
       subject: 'NFC Relay Alert: {{ .GroupLabels.alertname }}'
   ```

2. **Alert Rules**
   ```yaml
   # alert_rules.yml
   groups:
   - name: nfc_relay_alerts
     rules:
     - alert: HighErrorRate
       expr: rate(nfc_relay_errors_total[5m]) > 0.1
       for: 2m
       labels:
         severity: warning
       annotations:
         summary: "High error rate detected"
     
     - alert: ServiceDown
       expr: up{job="nfc-relay"} == 0
       for: 1m
       labels:
         severity: critical
       annotations:
         summary: "NFC Relay service is down"
   ```

## Backup and Recovery

### Data Backup Strategy

1. **Backup Configuration**
   ```bash
   #!/bin/bash
   # backup.sh
   
   BACKUP_DIR="/backup/nfc-relay"
   DATE=$(date +%Y%m%d_%H%M%S)
   
   # Create backup directory
   mkdir -p "$BACKUP_DIR/$DATE"
   
   # Backup configuration
   cp -r /opt/nfc-relay/config.yaml "$BACKUP_DIR/$DATE/"
   
   # Backup certificates (encrypted)
   tar -czf "$BACKUP_DIR/$DATE/certs.tar.gz" -C /opt/nfc-relay certs/
   
   # Backup data (encrypted)
   tar -czf "$BACKUP_DIR/$DATE/data.tar.gz" -C /opt/nfc-relay secure_data/
   
   # Backup logs
   tar -czf "$BACKUP_DIR/$DATE/logs.tar.gz" -C /opt/nfc-relay logs/
   
   # Encrypt backup
   gpg --cipher-algo AES256 --compress-algo 1 --symmetric --output "$BACKUP_DIR/$DATE.gpg" "$BACKUP_DIR/$DATE"
   
   # Clean up
   rm -rf "$BACKUP_DIR/$DATE"
   
   # Remove old backups (keep 30 days)
   find "$BACKUP_DIR" -name "*.gpg" -mtime +30 -delete
   ```

2. **Automated Backups**
   ```bash
   # Crontab entry
   0 2 * * * /opt/nfc-relay/scripts/backup.sh
   ```

### Disaster Recovery

1. **Recovery Procedures**
   ```bash
   #!/bin/bash
   # restore.sh
   
   BACKUP_FILE="$1"
   RESTORE_DIR="/opt/nfc-relay"
   
   if [ -z "$BACKUP_FILE" ]; then
       echo "Usage: $0 <backup_file.gpg>"
       exit 1
   fi
   
   # Decrypt backup
   gpg --decrypt "$BACKUP_FILE" | tar -xzf - -C /tmp/
   
   # Stop service
   sudo systemctl stop nfc-relay
   
   # Restore files
   cp -r /tmp/restore/config.yaml "$RESTORE_DIR/"
   tar -xzf /tmp/restore/certs.tar.gz -C "$RESTORE_DIR/"
   tar -xzf /tmp/restore/data.tar.gz -C "$RESTORE_DIR/"
   
   # Set permissions
   chmod 600 "$RESTORE_DIR/config.yaml"
   chmod 600 "$RESTORE_DIR/certs/"*.key
   chmod 700 "$RESTORE_DIR/secure_data"
   
   # Start service
   sudo systemctl start nfc-relay
   
   # Verify service
   sleep 5
   sudo systemctl status nfc-relay
   ```

## Performance Optimization

### Server Optimization

1. **System Tuning**
   ```bash
   # /etc/sysctl.d/99-nfc-relay.conf
   
   # Network optimization
   net.core.rmem_max = 16777216
   net.core.wmem_max = 16777216
   net.ipv4.tcp_rmem = 4096 87380 16777216
   net.ipv4.tcp_wmem = 4096 65536 16777216
   
   # File descriptor limits
   fs.file-max = 100000
   
   # Apply settings
   sudo sysctl -p /etc/sysctl.d/99-nfc-relay.conf
   ```

2. **Application Tuning**
   ```yaml
   # config.yaml
   server:
     worker_processes: auto  # CPU core count
     max_connections: 1000
     keepalive_timeout: 65
     client_max_body_size: 10M
   
   performance:
     enable_compression: true
     compression_level: 6
     enable_caching: true
     cache_ttl: 300
   ```

### Database Optimization

1. **Storage Optimization**
   ```python
   # Optimized storage settings
   storage:
     compression: "gzip"
     compression_level: 6
     batch_size: 1000
     write_buffer_size: 64MB
     cache_size: 256MB
   ```

2. **Indexing Strategy**
   ```python
   # Optimized data structures
   class OptimizedSessionStorage:
       def __init__(self):
           self.index_by_timestamp = {}
           self.index_by_session_id = {}
           self.index_by_card_id = {}
   ```

## Maintenance Procedures

### Regular Maintenance

1. **Daily Tasks**
   ```bash
   #!/bin/bash
   # daily_maintenance.sh
   
   # Check disk space
   df -h | grep -E "(80|90|9[0-9])%" && echo "WARNING: Disk space low"
   
   # Check log file sizes
   find /opt/nfc-relay/logs -name "*.log" -size +100M -exec echo "Large log file: {}" \;
   
   # Check service status
   systemctl is-active nfc-relay || echo "WARNING: Service not running"
   
   # Check certificate expiration
   openssl x509 -in /opt/nfc-relay/certs/server.crt -checkend 2592000 -noout || echo "WARNING: Certificate expires within 30 days"
   ```

2. **Weekly Tasks**
   ```bash
   #!/bin/bash
   # weekly_maintenance.sh
   
   # Rotate logs
   logrotate /etc/logrotate.d/nfc-relay
   
   # Clean old sessions
   python -m src.utils.cleanup --older-than 7d
   
   # Update dependencies
   source /opt/nfc-relay/venv/bin/activate
   pip list --outdated
   ```

3. **Monthly Tasks**
   ```bash
   #!/bin/bash
   # monthly_maintenance.sh
   
   # System updates
   sudo apt update && sudo apt upgrade -y
   
   # Security audit
   lynis audit system
   
   # Performance review
   python -m src.utils.performance_report --month
   ```

### Certificate Management

1. **Certificate Renewal**
   ```bash
   #!/bin/bash
   # renew_certs.sh
   
   # Let's Encrypt renewal
   certbot renew --quiet
   
   # Copy certificates
   cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem /opt/nfc-relay/certs/server.crt
   cp /etc/letsencrypt/live/yourdomain.com/privkey.pem /opt/nfc-relay/certs/server.key
   
   # Restart service
   sudo systemctl reload nfc-relay
   ```

2. **Certificate Monitoring**
   ```python
   # cert_monitor.py
   import ssl
   import socket
   from datetime import datetime, timedelta
   
   def check_certificate_expiry(hostname, port=8080):
       context = ssl.create_default_context()
       with socket.create_connection((hostname, port)) as sock:
           with context.wrap_socket(sock, server_hostname=hostname) as ssock:
               cert = ssock.getpeercert()
               expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
               days_until_expiry = (expiry_date - datetime.now()).days
               
               if days_until_expiry < 30:
                   send_alert(f"Certificate expires in {days_until_expiry} days")
   ```

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   # Check service status
   sudo systemctl status nfc-relay
   
   # Check logs
   sudo journalctl -u nfc-relay -f
   
   # Check configuration
   python server/config.py --validate
   
   # Check permissions
   ls -la /opt/nfc-relay/certs/
   ```

2. **Connection Issues**
   ```bash
   # Test connectivity
   telnet localhost 8080
   
   # Check firewall
   sudo ufw status
   
   # Check SSL/TLS
   openssl s_client -connect localhost:8080 -servername yourdomain.com
   ```

3. **Performance Issues**
   ```bash
   # Check resource usage
   htop
   
   # Check network
   iftop
   
   # Check disk I/O
   iotop
   
   # Application metrics
   curl -s https://localhost:8080/metrics | grep nfc_relay
   ```

### Log Analysis

1. **Error Investigation**
   ```bash
   # Search for errors
   grep -i error /opt/nfc-relay/logs/*.log
   
   # Analyze patterns
   awk '/ERROR/ {print $4}' /opt/nfc-relay/logs/nfc_relay.log | sort | uniq -c | sort -nr
   
   # Performance analysis
   grep "processing_time" /opt/nfc-relay/logs/nfc_relay.log | awk '{print $NF}' | sort -n
   ```

2. **Security Monitoring**
   ```bash
   # Failed authentication attempts
   grep "authentication_failed" /opt/nfc-relay/logs/security.log
   
   # Suspicious activity
   grep -E "(multiple_sessions|rapid_connections|invalid_protocol)" /opt/nfc-relay/logs/security.log
   ```

This deployment guide provides comprehensive instructions for secure, scalable deployment of the NFC Transit Card Relay System in production environments.