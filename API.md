# AI-SOC-Platform API Documentation

## Overview
AI-SOC-Platform provides a comprehensive REST API for security operations automation. All endpoints use JSON for request/response payloads and support real-time threat detection, incident response, and compliance monitoring.

## Base URL
```
http://localhost:5000/api
```

## Authentication
API endpoints require Bearer token authentication:
```
Authorization: Bearer <your-api-token>
```

## Endpoints

### Health Check
**GET** `/health`

Check API health and status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

### Threat Detection
**POST** `/detect-threats`

Detect threats using ML models on provided data.

**Request Body:**
```json
{
  "data": {
    "network_traffic": [],
    "system_events": [],
    "application_logs": []
  },
  "model": "isolation_forest"
}
```

**Response:**
```json
{
  "threats_detected": 5,
  "threat_level": 0.75,
  "threats": [
    {
      "threat_id": "TH-001",
      "type": "anomaly",
      "severity": "HIGH",
      "confidence": 0.92,
      "description": "Unusual network pattern detected"
    }
  ]
}
```

### Incident Response
**POST** `/respond-incident`

Automatic incident response execution.

**Request Body:**
```json
{
  "incident_id": "INC-001",
  "threat_level": 0.9,
  "incident_type": "malware_detection",
  "affected_systems": ["web-server-01", "db-server-02"]
}
```

**Response:**
```json
{
  "incident_id": "INC-001",
  "status": "RESPONDING",
  "actions_taken": [
    "Isolated affected systems",
    "Captured forensic data",
    "Initiated containment"
  ],
  "response_time_ms": 245
}
```

### Log Analysis
**POST** `/analyze-logs`

Analyze logs for anomalies and threats.

**Request Body:**
```json
{
  "logs": [
    "2024-01-15 10:30:00 ERROR Failed authentication from 192.168.1.100",
    "2024-01-15 10:30:05 WARNING Privilege escalation attempt detected"
  ]
}
```

**Response:**
```json
{
  "total_logs": 2,
  "anomalies_detected": 1,
  "threat_level": 0.65,
  "findings": [
    {
      "severity": "CRITICAL",
      "type": "failed_login",
      "count": 5,
      "anomaly_score": 0.8
    }
  ]
}
```

### Vulnerability Scan
**POST** `/scan-vulnerabilities`

Scan assets for vulnerabilities.

**Request Body:**
```json
{
  "assets": [
    {
      "id": "asset-001",
      "type": "server",
      "software_version": "Apache/2.4.49"
    }
  ]
}
```

**Response:**
```json
{
  "total_assets": 1,
  "vulnerabilities_found": 3,
  "critical_vulns": 1,
  "scan_details": [
    {
      "asset_id": "asset-001",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2024-1234",
          "severity": "CRITICAL",
          "cvss_score": 9.8
        }
      ]
    }
  ]
}
```

### Compliance Check
**POST** `/check-compliance`

Assess compliance against frameworks.

**Request Body:**
```json
{
  "framework": "PCI-DSS",
  "assets": [
    {
      "id": "asset-001",
      "patches_current": true,
      "access_controls_enabled": true,
      "audit_logging_enabled": true
    }
  ]
}
```

**Response:**
```json
{
  "framework": "PCI-DSS",
  "overall_status": "COMPLIANT",
  "compliance_percentage": 98.5,
  "findings": []
}
```

## Error Responses

All errors return standard format:

**400 Bad Request**
```json
{
  "error": "Invalid request",
  "message": "Missing required field: data"
}
```

**401 Unauthorized**
```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authentication token"
}
```

**500 Internal Server Error**
```json
{
  "error": "Internal server error",
  "message": "An unexpected error occurred"
}
```

## Integration Examples

### n8n Integration
Trigger SOC automation from n8n workflows:
```
URL: http://localhost:5000/api/detect-threats
Method: POST
Headers: Authorization: Bearer <token>
Body: {"data": workflow_data}
```

### Slack Integration
Receive alert notifications in Slack channel.

### Discord Integration
Send incident notifications to Discord webhooks.

## Rate Limiting
- 100 requests per minute per API token
- Returns 429 Too Many Requests when exceeded

## Webhooks
Supported webhook events:
- `threat.detected`
- `incident.created`
- `vulnerability.found`
- `compliance.drift`
