from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import socket
import requests
import time

app = FastAPI(title="CyberPulse Scanning Engine")

# Allow Frontend to communicate
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options"
]

def scan_ports(target: str):
    open_ports = []
    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append({"port": port, "service": service})
        sock.close()
    return open_ports

def scan_headers(target: str):
    headers_report = {"missing": [], "present": []}
    url = f"http://{target}"
    if not target.startswith("http"):
        url = f"https://{target}"
    
    try:
        response = requests.get(url, timeout=3, verify=False)
        for header in SECURITY_HEADERS:
            if header in response.headers:
                headers_report["present"].append(header)
            else:
                headers_report["missing"].append(header)
    except requests.exceptions.RequestException:
        headers_report["error"] = "Could not connect to target for HTTP analysis."
    
    return headers_report

@app.post("/api/scan")
def run_scan(req: ScanRequest):
    target = req.target.replace("http://", "").replace("https://", "").split("/")[0]
    
    if not target:
        raise HTTPException(status_code=400, detail="Invalid Target")
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Could not resolve target domain")

    start_time = time.time()
    
    # 1. Port Scan
    ports = scan_ports(target_ip)
    
    # 2. Header Scan
    headers = scan_headers(target)
    
    # 3. Calculate Threat Score (0 is secure, 100 is critical)
    threat_score = 0
    risk_level = "Low"
    
    # Penalize for open dangerous ports
    dangerous_ports = [21, 23, 3389]
    for p in ports:
        if p["port"] in dangerous_ports:
            threat_score += 30
        else:
            threat_score += 5
            
    # Penalize for missing security headers
    if "missing" in headers:
        threat_score += len(headers["missing"]) * 10
        
    threat_score = min(threat_score, 100)
    
    if threat_score > 70:
        risk_level = "Critical"
    elif threat_score > 40:
        risk_level = "High"
    elif threat_score > 20:
        risk_level = "Medium"
    
    scan_duration = round(time.time() - start_time, 2)

    return {
        "target": target,
        "ip_address": target_ip,
        "threat_score": threat_score,
        "risk_level": risk_level,
        "open_ports": ports,
        "security_headers": headers,
        "scan_duration_seconds": scan_duration
    }
