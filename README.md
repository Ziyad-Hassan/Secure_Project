# Installation and Running the Application

Install dependencies:
```bash
npm install
```


Create environment file and place your secrets:
```bash
touch .env
```


Run the application:
```bash
npm run dev
```



The application runs locally on:
```bash
http://localhost:5000
```


## Dynamic Application Security Testing (DAST)

### OWASP ZAP – Automated Scan
1. Start the application
2. Launch OWASP ZAP
3. Select Automated Scan
4. Target the following URL:
http://localhost:5000
Click Attack


---

## Static Application Security Testing (SAST) with Semgrep

### 1) Basic rules only (no JSON) 


```bash
semgrep --config p/javascript --config p/nodejs
```
### 2) Basic + custom rules (no JSON)
```bash
semgrep --config p/javascript --config p/nodejs --config semgrep/custom-rules.yaml
```
### 3) Basic + custom rules → single JSON output
```bash
semgrep --config p/javascript --config p/nodejs --config semgrep/custom-rules.yaml -
json > semgrep-all-results.json
```



