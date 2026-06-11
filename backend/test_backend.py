from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_scan_api():
    print("Testing CyberPulse Backend API...")
    response = client.post("/api/scan", json={"target": "example.com"})
    
    if response.status_code == 200:
        data = response.json()
        print("[PASS] API Returned 200 OK")
        print(f"Target: {data['target']}")
        print(f"IP Address: {data['ip_address']}")
        print(f"Threat Score: {data['threat_score']}")
        print(f"Risk Level: {data['risk_level']}")
        
        assert "open_ports" in data
        assert "security_headers" in data
        
        print("✅ Backend Engine is fully operational.")
    else:
        print(f"[FAIL] Backend returned status code {response.status_code}")
        print(response.json())

if __name__ == "__main__":
    test_scan_api()
