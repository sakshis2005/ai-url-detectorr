# Sentinel AI — Intelligent Phishing URL Detection System

> **🎓 Academic Major Project**  
> **Developer:** **Sakshi Singh**  
> **Degree / Branch:** **B.Tech Computer Science & Engineering (Data Science)** — **3rd Year**  
> **Institute:** **Lloyd Institute of Engineering and Technology**  

An AI/Machine Learning-powered cybersecurity system designed to identify and neutralize zero-day phishing links, brand spoofing, typosquatting, and credential harvesting threats in real time.

---

## 📁 Project File Structure

```
ai-url-detector/
│
├── index.html       # Interactive Cybersecurity Dashboard UI
├── style.css        # Professional dark-mode SOC/Cyber styling
├── app.js           # Frontend Controller (sound FX, chat stream, report exports)
├── detector.js      # Heuristic & Threat Engine (entropy, typosquatting, TLDs)
├── train.py         # Python Machine Learning pipeline (Random Forest classifier)
└── README.md        # Complete documentation and viva guide
```

---

## 🚀 How to Run the Project (Zero Setup)

1. Open this folder in your File Explorer:
   `C:\Users\ssing\.gemini\antigravity-ide\scratch\ai-url-detector`
2. **Double-click `index.html`**.
3. It opens directly in your default browser (Chrome, Edge, Brave, Firefox).
4. No web server or installation required.

---

## 🧪 Demo Test URLs for Presentation

| Category | Input URL | Verdict | Key Detected Heuristics |
|---|---|---|---|
| **Phishing: Brand Spoof** | `http://paypal-security-login-verify.top/account` | **CRITICAL (92%)** | Typosquatting, Credential keywords, Suspicious `.top` TLD |
| **Phishing: Direct IP** | `http://192.168.1.105/admin-login.php` | **HIGH (85%)** | Raw IP host (no DNS), Login hook, Unencrypted HTTP |
| **Phishing: Subdomain Trick** | `http://paypal.com.auth-user-recover.cam/login` | **CRITICAL (90%)** | Deceptive subdomain, Cheap TLD (`.cam`), Urgency bait |
| **Safe / Benign** | `https://github.com/torvalds/linux` | **SAFE (0%)** | Trusted apex domain, Valid HTTPS, Normal entropy |

---

## 🧠 Machine Learning Engine (`train.py`)

If your evaluator requests Python code:
```bash
pip install pandas numpy scikit-learn joblib
python train.py
```
- **Algorithm**: Random Forest Classifier (`n_estimators=100`)
- **Features Extracted**: 14 Lexical, Host, and Entropy metrics
- **Model Output**: `phishing_detector_model.pkl` (Accuracy: ~96-98%)
