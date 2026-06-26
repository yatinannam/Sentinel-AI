import os
import sys
import math
import json
import re
import requests
import joblib
import numpy as np

# Map model outputs to text labels
CLASS_MAP = {
    0: "Safe",
    1: "Trojan",
    2: "Ransomware",
    3: "Spyware",
    4: "Cryptominer"
}

SEVERITY_MAP = {
    "Safe": "low",
    "Trojan": "high",
    "Ransomware": "critical",
    "Spyware": "high",
    "Cryptominer": "medium"
}

def calculate_entropy(file_path):
    """Calculates Shannon entropy of a file to check for packing/encryption."""
    if not os.path.exists(file_path):
        return 0.0
    
    total_bytes = os.path.getsize(file_path)
    if total_bytes == 0:
        return 0.0

    counts = [0] * 256
    with open(file_path, 'rb') as f:
        # Read in chunks to handle large files
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            for byte in chunk:
                counts[byte] += 1

    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / total_bytes
        entropy -= p * math.log2(p)
        
    return round(entropy, 2)

def extract_features(file_path):
    """Extracts features from target executable for the model."""
    file_size_kb = os.path.getsize(file_path) / 1024.0
    entropy = calculate_entropy(file_path)

    # Key security-sensitive API imports/strings
    apis = [
        b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", 
        b"QueueUserAPC", b"NtCreateThreadEx", b"SetWindowsHookEx", b"GetAsyncKeyState"
    ]
    
    # Generic malicious indicator strings
    suspicious_strings = [
        b"powershell", b"bypass", b"iex", b"downloadstring", b"stratum+tcp",
        b"shadowcopy", b"vssadmin", b"cmd.exe", b"taskkill", b"reg add"
    ]

    api_matches = 0
    string_matches = 0

    try:
        # Scan file content for strings
        with open(file_path, 'rb') as f:
            content = f.read(10 * 1024 * 1024) # Scan first 10MB max
            
            for api in apis:
                if api.lower() in content.lower():
                    api_matches += 1
            
            for s in suspicious_strings:
                if s.lower() in content.lower():
                    string_matches += 1
    except Exception:
        pass

    return file_size_kb, entropy, api_matches, string_matches

def check_virustotal(file_hash, api_key):
    """Verifies suspicious hashes against VirusTotal API."""
    if not api_key:
        return None
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            return {
                "ratio": f"{malicious}/{total}",
                "reputation": data['data']['attributes'].get('reputation', 0),
                "family": data['data']['attributes'].get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')
            }
    except Exception:
        pass
    return None

def analyze_file(file_path, vt_api_key=None):
    if not os.path.exists(file_path):
        return {"error": "File not found"}

    file_size_kb, entropy, api_count, string_count = extract_features(file_path)
    
    # 1. Load trained classifier
    model_path = os.path.join(os.path.dirname(__file__), 'malware_classifier.pkl')
    
    # Fallback if model is not trained yet (heuristics model)
    if not os.path.exists(model_path):
        # Heuristic scoring
        score = 0
        reasons = []
        if entropy > 7.0:
            score += 40
            reasons.append("High entropy indicating encrypted/packed content")
        if api_count >= 2:
            score += 30
            reasons.append(f"Abuse of system APIs: {api_count} matches found")
        if string_count >= 2:
            score += 30
            reasons.append("Suspicious command-line or system string signatures")

        threat_type = "Trojan" if score >= 40 else "Safe"
        confidence = score if score > 0 else 100
        if threat_type == "Safe":
            confidence = 99
    else:
        model = joblib.load(model_path)
        features = np.array([[file_size_kb, entropy, api_count, string_count]])
        
        pred = model.predict(features)[0]
        prob = model.predict_proba(features)[0]
        
        threat_type = CLASS_MAP[pred]
        confidence = int(prob[pred] * 100)
        
        # Build explainable AI (XAI) reasons based on telemetry
        reasons = []
        if entropy > 6.8:
            reasons.append(f"High Shannon entropy ({entropy}) suggests binary obfuscation or packer usage")
        if api_count > 0:
            reasons.append(f"Contains {api_count} API call references linked to memory injection or hooking")
        if string_count > 0:
            reasons.append(f"Identified {string_count} command scripts associated with persistence or defense evasion")
        if file_size_kb < 100 and threat_type != "Safe":
            reasons.append("Highly compact payload size typical of targeted drop loaders")
            
        if not reasons and threat_type != "Safe":
            reasons.append("Behavioral model classifies code signatures as anomalous")

    # 2. VirusTotal verification layer
    vt_result = None
    if threat_type != "Safe" and vt_api_key:
        import hashlib
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        file_hash = hasher.hexdigest()
        vt_result = check_virustotal(file_hash, vt_api_key)

    result = {
        "status": "analyzed",
        "threatType": threat_type,
        "severity": SEVERITY_MAP[threat_type],
        "confidence": confidence,
        "features": {
            "fileSizeKb": round(file_size_kb, 2),
            "entropy": entropy,
            "apiCount": api_count,
            "stringCount": string_count
        },
        "reasons": reasons,
        "virusTotal": vt_result
    }
    
    return result

if __name__ == "__main__":
    # Expect single JSON argument on stdin
    # Format: {"filePath": "C:\\path\\file.exe", "apiKey": "optional_vt_key"}
    try:
        input_data = json.loads(sys.stdin.read())
        filePath = input_data.get('filePath')
        apiKey = input_data.get('apiKey')
        
        if not filePath:
            print(json.dumps({"error": "No filePath provided"}))
            sys.exit(1)
            
        result = analyze_file(filePath, apiKey)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
