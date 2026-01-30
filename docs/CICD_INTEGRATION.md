# CTPPO CI/CD Integration Guide
## Automated Security Scanning in Your Pipeline

---

## 🚀 Overview

CTPPO can be integrated into your CI/CD pipeline to:
- **Block deployments** with critical vulnerabilities
- **Generate security reports** for each build
- **Track security posture** over time
- **Enforce security gates** before production

---

## 📦 Integration Methods

### Method 1: REST API Integration (Recommended)

CTPPO exposes REST APIs that can be called from any CI/CD tool.

```bash
# Base URL (when running locally)
CTPPO_URL="http://localhost:8000"

# Or production URL
CTPPO_URL="https://ctppo.your-company.com"
```

---

## 🔧 GitHub Actions Integration

### `.github/workflows/security-scan.yml`

```yaml
name: Security Scan with CTPPO

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  CTPPO_URL: ${{ secrets.CTPPO_URL }}
  CTPPO_USERNAME: ${{ secrets.CTPPO_USERNAME }}
  CTPPO_PASSWORD: ${{ secrets.CTPPO_PASSWORD }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Get CTPPO Auth Token
        id: auth
        run: |
          TOKEN=$(curl -s -X POST "$CTPPO_URL/api/auth/login" \
            -H "Content-Type: application/json" \
            -d '{"email": "${{ env.CTPPO_USERNAME }}", "password": "${{ env.CTPPO_PASSWORD }}"}' \
            | jq -r '.access_token')
          echo "token=$TOKEN" >> $GITHUB_OUTPUT

      - name: Run Security Scan
        id: scan
        run: |
          # Scan your staging/preview URL
          SCAN_RESULT=$(curl -s -X POST "$CTPPO_URL/api/scan/target" \
            -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
            -H "Content-Type: application/json" \
            -d '{
              "target": "${{ vars.STAGING_URL }}",
              "scan_type": "full",
              "include_web_scan": true
            }')
          
          echo "$SCAN_RESULT" > scan-result.json
          
          # Extract risk level
          RISK_LEVEL=$(echo "$SCAN_RESULT" | jq -r '.risk_summary.risk_level')
          echo "risk_level=$RISK_LEVEL" >> $GITHUB_OUTPUT
          
          # Extract vulnerability counts
          CRITICAL=$(echo "$SCAN_RESULT" | jq -r '.risk_summary.vulnerabilities.critical // 0')
          HIGH=$(echo "$SCAN_RESULT" | jq -r '.risk_summary.vulnerabilities.high // 0')
          echo "critical=$CRITICAL" >> $GITHUB_OUTPUT
          echo "high=$HIGH" >> $GITHUB_OUTPUT

      - name: Generate PDF Report
        run: |
          curl -s -X POST "$CTPPO_URL/api/reports/scan-pdf" \
            -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
            -H "Content-Type: application/json" \
            -d @scan-result.json \
            -o security-report.pdf

      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: |
            scan-result.json
            security-report.pdf

      - name: Security Gate Check
        run: |
          RISK="${{ steps.scan.outputs.risk_level }}"
          CRITICAL="${{ steps.scan.outputs.critical }}"
          HIGH="${{ steps.scan.outputs.high }}"
          
          echo "🛡️ Security Scan Results:"
          echo "   Risk Level: $RISK"
          echo "   Critical: $CRITICAL"
          echo "   High: $HIGH"
          
          # Fail if critical vulnerabilities found
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ CRITICAL vulnerabilities found! Blocking deployment."
            exit 1
          fi
          
          # Warn on high vulnerabilities
          if [ "$HIGH" -gt 5 ]; then
            echo "⚠️ WARNING: Multiple HIGH severity vulnerabilities found."
            echo "   Review security-report.pdf for details."
          fi
          
          echo "✅ Security gate passed!"

      - name: Comment PR with Results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const result = JSON.parse(fs.readFileSync('scan-result.json'));
            
            const risk = result.risk_summary.risk_level;
            const vulns = result.risk_summary.vulnerabilities;
            
            const emoji = {
              'CRITICAL': '🔴',
              'HIGH': '🟠', 
              'MEDIUM': '🟡',
              'LOW': '🟢'
            };
            
            const body = `## 🛡️ CTPPO Security Scan Results
            
            **Risk Level:** ${emoji[risk] || '⚪'} ${risk}
            
            | Severity | Count |
            |----------|-------|
            | Critical | ${vulns.critical || 0} |
            | High | ${vulns.high || 0} |
            | Medium | ${vulns.medium || 0} |
            | Low | ${vulns.low || 0} |
            
            📄 [Download Full Report](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

---

## 🔧 GitLab CI Integration

### `.gitlab-ci.yml`

```yaml
stages:
  - build
  - test
  - security
  - deploy

variables:
  CTPPO_URL: ${CTPPO_URL}

security-scan:
  stage: security
  image: curlimages/curl:latest
  before_script:
    - apk add --no-cache jq
  script:
    # Authenticate
    - |
      TOKEN=$(curl -s -X POST "$CTPPO_URL/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"$CTPPO_USERNAME\", \"password\": \"$CTPPO_PASSWORD\"}" \
        | jq -r '.access_token')
    
    # Run scan
    - |
      curl -s -X POST "$CTPPO_URL/api/scan/target" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$STAGING_URL\", \"scan_type\": \"full\"}" \
        > scan-result.json
    
    # Check results
    - |
      RISK=$(jq -r '.risk_summary.risk_level' scan-result.json)
      CRITICAL=$(jq -r '.risk_summary.vulnerabilities.critical // 0' scan-result.json)
      
      echo "Risk Level: $RISK"
      echo "Critical Vulnerabilities: $CRITICAL"
      
      if [ "$CRITICAL" -gt 0 ]; then
        echo "Security gate failed!"
        exit 1
      fi
  artifacts:
    paths:
      - scan-result.json
    reports:
      dotenv: security.env
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

---

## 🔧 Jenkins Pipeline Integration

### `Jenkinsfile`

```groovy
pipeline {
    agent any
    
    environment {
        CTPPO_URL = credentials('ctppo-url')
        CTPPO_CREDS = credentials('ctppo-credentials')
    }
    
    stages {
        stage('Build') {
            steps {
                sh 'npm install && npm run build'
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    // Get auth token
                    def authResponse = sh(
                        script: """
                            curl -s -X POST "${CTPPO_URL}/api/auth/login" \
                                -H "Content-Type: application/json" \
                                -d '{"email": "${CTPPO_CREDS_USR}", "password": "${CTPPO_CREDS_PSW}"}'
                        """,
                        returnStdout: true
                    )
                    def token = readJSON(text: authResponse).access_token
                    
                    // Run security scan
                    def scanResponse = sh(
                        script: """
                            curl -s -X POST "${CTPPO_URL}/api/scan/target" \
                                -H "Authorization: Bearer ${token}" \
                                -H "Content-Type: application/json" \
                                -d '{"target": "${env.STAGING_URL}", "scan_type": "full"}'
                        """,
                        returnStdout: true
                    )
                    
                    writeFile file: 'scan-result.json', text: scanResponse
                    
                    def result = readJSON(text: scanResponse)
                    def riskLevel = result.risk_summary.risk_level
                    def critical = result.risk_summary.vulnerabilities?.critical ?: 0
                    
                    echo "🛡️ Risk Level: ${riskLevel}"
                    echo "🔴 Critical: ${critical}"
                    
                    // Security gate
                    if (critical > 0) {
                        error("Security gate failed: ${critical} critical vulnerabilities found!")
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'scan-result.json', fingerprint: true
                }
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'npm run deploy'
            }
        }
    }
}
```

---

## 🔧 Azure DevOps Pipeline

### `azure-pipelines.yml`

```yaml
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: ctppo-secrets

stages:
  - stage: SecurityScan
    jobs:
      - job: ScanApplication
        steps:
          - task: Bash@3
            displayName: 'CTPPO Security Scan'
            inputs:
              targetType: 'inline'
              script: |
                # Authenticate
                TOKEN=$(curl -s -X POST "$(CTPPO_URL)/api/auth/login" \
                  -H "Content-Type: application/json" \
                  -d '{"email": "$(CTPPO_EMAIL)", "password": "$(CTPPO_PASSWORD)"}' \
                  | jq -r '.access_token')
                
                # Run scan
                curl -s -X POST "$(CTPPO_URL)/api/scan/target" \
                  -H "Authorization: Bearer $TOKEN" \
                  -H "Content-Type: application/json" \
                  -d '{"target": "$(STAGING_URL)", "scan_type": "full"}' \
                  > $(Build.ArtifactStagingDirectory)/scan-result.json
                
                # Check results
                CRITICAL=$(jq -r '.risk_summary.vulnerabilities.critical // 0' \
                  $(Build.ArtifactStagingDirectory)/scan-result.json)
                
                if [ "$CRITICAL" -gt 0 ]; then
                  echo "##vso[task.logissue type=error]Critical vulnerabilities found!"
                  exit 1
                fi
          
          - task: PublishBuildArtifacts@1
            displayName: 'Publish Security Report'
            inputs:
              PathtoPublish: '$(Build.ArtifactStagingDirectory)'
              ArtifactName: 'security-report'
```

---

## 🐳 Docker-based CI Integration

### Standalone Scanner Container

```dockerfile
# Dockerfile.scanner
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install requests

COPY ci-scanner.py .

ENTRYPOINT ["python", "ci-scanner.py"]
```

### `ci-scanner.py`

```python
#!/usr/bin/env python3
"""
CTPPO CI Scanner
Usage: python ci-scanner.py --target https://example.com --fail-on critical
"""

import os
import sys
import json
import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description='CTPPO CI Security Scanner')
    parser.add_argument('--target', required=True, help='URL to scan')
    parser.add_argument('--ctppo-url', default=os.environ.get('CTPPO_URL', 'http://localhost:8000'))
    parser.add_argument('--email', default=os.environ.get('CTPPO_EMAIL'))
    parser.add_argument('--password', default=os.environ.get('CTPPO_PASSWORD'))
    parser.add_argument('--scan-type', default='full', choices=['quick', 'full', 'web'])
    parser.add_argument('--fail-on', default='critical', choices=['critical', 'high', 'medium', 'none'])
    parser.add_argument('--output', default='scan-result.json')
    
    args = parser.parse_args()
    
    # Authenticate
    print(f"🔐 Authenticating with CTPPO...")
    auth_response = requests.post(
        f"{args.ctppo_url}/api/auth/login",
        json={"email": args.email, "password": args.password}
    )
    
    if not auth_response.ok:
        print(f"❌ Authentication failed: {auth_response.text}")
        sys.exit(1)
    
    token = auth_response.json()['access_token']
    headers = {"Authorization": f"Bearer {token}"}
    
    # Run scan
    print(f"🔍 Scanning {args.target}...")
    scan_response = requests.post(
        f"{args.ctppo_url}/api/scan/target",
        headers=headers,
        json={
            "target": args.target,
            "scan_type": args.scan_type,
            "include_web_scan": True
        }
    )
    
    if not scan_response.ok:
        print(f"❌ Scan failed: {scan_response.text}")
        sys.exit(1)
    
    result = scan_response.json()
    
    # Save result
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"📄 Results saved to {args.output}")
    
    # Display summary
    risk = result.get('risk_summary', {})
    vulns = risk.get('vulnerabilities', {})
    
    print(f"\n{'='*50}")
    print(f"🛡️  CTPPO Security Scan Results")
    print(f"{'='*50}")
    print(f"Risk Level: {risk.get('risk_level', 'UNKNOWN')}")
    print(f"Critical:   {vulns.get('critical', 0)}")
    print(f"High:       {vulns.get('high', 0)}")
    print(f"Medium:     {vulns.get('medium', 0)}")
    print(f"Low:        {vulns.get('low', 0)}")
    print(f"{'='*50}\n")
    
    # Security gate
    fail_thresholds = {
        'critical': vulns.get('critical', 0) > 0,
        'high': vulns.get('critical', 0) > 0 or vulns.get('high', 0) > 0,
        'medium': vulns.get('critical', 0) > 0 or vulns.get('high', 0) > 0 or vulns.get('medium', 0) > 0,
        'none': False
    }
    
    if fail_thresholds.get(args.fail_on, False):
        print(f"❌ Security gate FAILED (--fail-on {args.fail_on})")
        sys.exit(1)
    
    print("✅ Security gate PASSED")
    sys.exit(0)

if __name__ == '__main__':
    main()
```

### Usage in CI:

```bash
# Run scanner
docker run --rm \
  -e CTPPO_URL=https://ctppo.company.com \
  -e CTPPO_EMAIL=ci@company.com \
  -e CTPPO_PASSWORD=secret \
  ctppo-scanner:latest \
  --target https://staging.app.com \
  --fail-on critical
```

---

## 🎯 Best Practices

### 1. **Scan Timing**
- Scan after deployment to staging
- Scan before production deployment
- Scan on PR/MR for changed services

### 2. **Gate Policies**
```
┌─────────────────────────────────────────────────┐
│           RECOMMENDED GATE POLICIES             │
├─────────────────────────────────────────────────┤
│ Stage          │ Fail On        │ Action       │
├─────────────────────────────────────────────────┤
│ PR/MR          │ Critical       │ Block merge  │
│ Staging        │ Critical+High  │ Warn & log   │
│ Pre-Production │ Critical       │ Block deploy │
│ Production     │ Critical       │ Alert & log  │
└─────────────────────────────────────────────────┘
```

### 3. **Secrets Management**
- Store CTPPO credentials in CI secrets
- Use service accounts, not personal accounts
- Rotate credentials regularly

### 4. **Report Retention**
- Archive scan reports as build artifacts
- Track trends over time
- Set up dashboards for visibility

---

## 📊 Example Dashboard Query (Grafana/ELK)

```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"scan_type": "ci-cd"}},
        {"range": {"@timestamp": {"gte": "now-30d"}}}
      ]
    }
  },
  "aggs": {
    "by_repo": {
      "terms": {"field": "repository.keyword"},
      "aggs": {
        "critical_vulns": {"sum": {"field": "vulnerabilities.critical"}}
      }
    }
  }
}
```

---

*Integrate early, scan often, fix fast!* 🚀
