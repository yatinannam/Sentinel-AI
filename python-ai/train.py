import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

def train_mock_model():
    print("Generating training dataset...")
    # Features: [file_size_kb, entropy, suspicious_api_count, suspicious_string_count]
    # Classes: 0=Safe, 1=Trojan, 2=Ransomware, 3=Spyware, 4=Cryptominer
    
    X = []
    y = []

    # 1. Safe files
    for _ in range(200):
        file_size = np.random.uniform(50, 5000) # 50KB to 5MB
        entropy = np.random.uniform(3.0, 5.8)
        apis = np.random.randint(0, 2)
        strings = np.random.randint(0, 2)
        X.append([file_size, entropy, apis, strings])
        y.append(0)

    # 2. Trojans (Packed, high entropy, injection APIs, web request strings)
    for _ in range(100):
        file_size = np.random.uniform(10, 1500)
        entropy = np.random.uniform(6.5, 7.9)
        apis = np.random.randint(2, 6)
        strings = np.random.randint(2, 5)
        X.append([file_size, entropy, apis, strings])
        y.append(1)

    # 3. Ransomware (VSS shadow copy delete strings, high entropy, encryption API)
    for _ in range(100):
        file_size = np.random.uniform(20, 800)
        entropy = np.random.uniform(7.0, 7.99)
        apis = np.random.randint(1, 4)
        strings = np.random.randint(3, 7)
        X.append([file_size, entropy, apis, strings])
        y.append(2)

    # 4. Spyware (Keystroke hook APIs, registry Run startup strings, low-mid entropy)
    for _ in range(100):
        file_size = np.random.uniform(15, 600)
        entropy = np.random.uniform(4.5, 6.2)
        apis = np.random.randint(3, 5)
        strings = np.random.randint(2, 4)
        X.append([file_size, entropy, apis, strings])
        y.append(3)

    # 5. Cryptominers (Stratum pool strings, high CPU threads API, mid entropy)
    for _ in range(100):
        file_size = np.random.uniform(100, 3000)
        entropy = np.random.uniform(5.5, 6.8)
        apis = np.random.randint(1, 3)
        strings = np.random.randint(3, 6)
        X.append([file_size, entropy, apis, strings])
        y.append(4)

    X = np.array(X)
    y = np.array(y)

    print(f"Training Random Forest Classifier on {len(X)} samples...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)

    model_path = os.path.join(os.path.dirname(__file__), 'malware_classifier.pkl')
    joblib.dump(model, model_path)
    print(f"Model successfully saved to {model_path}")

if __name__ == "__main__":
    train_mock_model()
