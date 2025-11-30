# AI-SOC-Platform Deployment Guide

## Quick Start (Docker)

The fastest way to deploy AI-SOC-Platform is using Docker and Docker Compose.

### Prerequisites
- Docker (v20.10+)
- Docker Compose (v1.29+)
- 4GB RAM minimum
- 20GB disk space minimum

### Single Command Deployment

```bash
docker-compose up -d
```

This command will:
1. Pull all required images
2. Create persistent volumes
3. Start all services (API, PostgreSQL, Redis, Elasticsearch, Kibana)
4. Initialize databases
5. Start the SOC platform

### Verify Deployment

```bash
# Check if all containers are running
docker-compose ps

# Check API health
curl http://localhost:5000/api/health

# Check Kibana dashboard
# Open http://localhost:5601 in browser
```

## Manual Deployment

### 1. Install Dependencies

```bash
# Clone repository
git clone https://github.com/rishikumarbommakanti-ops/AI-SOC-Platform.git
cd AI-SOC-Platform

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Configure Services

Create `.env` file:
```
FLASK_ENV=production
DATABASE_URL=postgresql://user:password@localhost:5432/socdatabase
REDIS_URL=redis://localhost:6379/0
ELASTIC_HOST=localhost
ELASTIC_PORT=9200
```

### 3. Start Services

```bash
# Start PostgreSQL
# Already running in docker-compose

# Start Redis
# Already running in docker-compose

# Start Elasticsearch
# Already running in docker-compose

# Start Flask API
python src/main.py
```

## Production Deployment

### Kubernetes Deployment

```bash
# Create namespace
kubectl create namespace soc-platform

# Deploy
kubectl apply -f k8s/ -n soc-platform

# Check deployment
kubectl get pods -n soc-platform
```

### High Availability Setup

1. **Load Balancing**: Use Nginx/HAProxy
2. **Database Replication**: PostgreSQL replication
3. **Cache Redundancy**: Redis Sentinel
4. **Log Aggregation**: Multiple Elasticsearch nodes

## Configuration

### Environment Variables

```
FLASK_ENV              # development or production
DATABASE_URL           # PostgreSQL connection string
REDIS_URL              # Redis connection string
ELASTIC_HOST           # Elasticsearch hostname
ELASTIC_PORT           # Elasticsearch port
LOG_LEVEL              # DEBUG, INFO, WARNING, ERROR
API_WORKERS            # Number of gunicorn workers
```

## Monitoring

### Access Points

- **API**: http://localhost:5000
- **Kibana**: http://localhost:5601
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379
- **Elasticsearch**: localhost:9200

### Health Checks

```bash
# API Health
curl http://localhost:5000/api/health

# Elasticsearch Status
curl http://localhost:9200/_cluster/health

# Redis Status
redis-cli ping
```

## Backup & Recovery

### Database Backup

```bash
# Backup PostgreSQL
docker-compose exec -T postgres pg_dump -U socdba socdatabase > backup.sql

# Restore PostgreSQL
docker-compose exec -T postgres psql -U socdba socdatabase < backup.sql
```

### Volume Backup

```bash
# Backup all volumes
docker run --rm -v soc_postgres_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/postgres_backup.tar.gz -C /data .
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs -f <service-name>

# Rebuild container
docker-compose build --no-cache <service-name>
```

### Database Connection Error

```bash
# Verify PostgreSQL is running
docker-compose ps postgres

# Check connection
psql postgresql://user:password@localhost:5432/socdatabase
```

### High Memory Usage

```bash
# Limit container memory
docker update --memory 2g container_id

# Check memory usage
docker stats
```

## Performance Tuning

### PostgreSQL

```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM threats;

-- Create indexes
CREATE INDEX idx_threats_timestamp ON threats(timestamp);
```

### Elasticsearch

```bash
# Increase heap size in docker-compose.yml
ES_JAVA_OPTS: "-Xms2g -Xmx2g"
```

### Redis

```bash
# Check memory usage
redis-cli INFO memory

# Clear old data
redis-cli FLUSHDB
```

## Security Hardening

1. **Change Default Passwords**: Update PostgreSQL and Elasticsearch credentials
2. **Enable SSL/TLS**: Use reverse proxy with SSL certificates
3. **API Authentication**: Generate strong API tokens
4. **Network Segmentation**: Use Docker networks appropriately
5. **Firewall Rules**: Restrict access to service ports

## Updates & Maintenance

### Update to Latest Version

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose build

# Restart services
docker-compose up -d
```

### Regular Maintenance

- Daily: Check API health
- Weekly: Review logs for errors
- Monthly: Update dependencies
- Quarterly: Full backup and restore test

## Support & Issues

For issues or questions:
1. Check documentation in README.md
2. Review API.md for endpoint details
3. Check container logs
4. Create GitHub issue with detailed information
