import os
import re
import uvicorn
import joblib
import pandas as pd
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from extract_url import extract_url

app = FastAPI(title="PhishiFy Backend", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pre-load models
try:
    text_model = joblib.load("model/phish_text_model.joblib")
    vectorizer = joblib.load("model/tfidf_vectorizer.joblib")
except Exception as e:
    text_model, vectorizer = None, None

try:
    url_model = joblib.load("model/phish_feature_model.joblib")
except Exception as e:
    url_model = None

class EmailRequest(BaseModel):
    sender: Optional[str] = None
    subject: Optional[str] = None
    bodyText: Optional[str] = None
    links: Optional[List[dict]] = None
    attachments: Optional[List[dict]] = None

def analyze_links(links: List[dict]):
    if not links or not url_model:
        return 0.0
    
    max_prob = 0.0
    for link in links:
        url = link.get("url", "")
        if not url: continue
        try:
            feats = extract_url(url)
            # If the domain is whitelisted/safe, risk is effectively 0
            if feats.get("is_safe_domain", 0) == 1:
                continue

            # Fallback heuristic for obviously suspicious domains (run regardless of model)
            url_lower = url.lower()
            suspicious_keywords = [".exe", ".es/", "apply", "login", "verify", "secure", "billing", "invoice", "auth", "update", "account"]
            if any(k in url_lower for k in suspicious_keywords) and feats.get("is_safe_domain", 0) == 0:
                max_prob = max(max_prob, 0.85)

            expected_cols = url_model.feature_names_in_
            df = pd.DataFrame([[feats.get(c, 0) for c in expected_cols]], columns=expected_cols)
            df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
            
            prob = float(url_model.predict_proba(df)[0][1])
            calibrated_prob = max(0.0, prob - 0.40) * 1.6 
            max_prob = max(max_prob, calibrated_prob)
        except Exception as e:
            print("URL Analysis error:", e)
    return max_prob

def sandbox_analyze_attachments(attachments: List[dict]):
    if not attachments:
        return 0.0
    # Include .html and .htm that are common in HTML Smuggling alongside executeables
    high_risk_ext = ['.exe', '.scr', '.vbs', '.bat', '.cmd', '.js', '.ps1', '.docm', '.xlsm']
    medium_risk_ext = ['.html', '.htm', '.svg']
    
    suspicious_count = 0
    for att in attachments:
        name = att.get("name", "").lower()
        if any(name.endswith(ext) for ext in high_risk_ext):
            suspicious_count += 1
        if any(name.endswith(ext) for ext in medium_risk_ext):
            suspicious_count += 0.5
            
    return min(1.0, (suspicious_count * 0.4)) 

def osint_check_sender(sender: str):
    if not sender:
        return 0.0
    
    known_safe = ["google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com"]
    # Provide a bonus negative risk for verified known safe domains if they match exactly
    if any(sender.endswith("@" + domain) for domain in known_safe):
        return -0.3

    known_bad = ["fake-support", "admin-verify", "paypal-auth", "login.com", "-secure", "-auth", "-update"]
    if any(b in sender.lower() for b in known_bad):
         return 0.7
    return 0.0

@app.post("/predict_email")
def predict_email(data: EmailRequest):
    try:
        # 1. NLP Text Analysis & Code Injection Heuristics
        text_content = f"{data.subject or ''} {data.bodyText or ''}".strip()
        text_lower = text_content.lower()
        nlp_prob = 0.0
        
        # Check for HTML Smuggling / Script Injection patterns directly
        smuggling_keywords = ["<script", "document.createelement", "window.onload", "document.body.append", "function()", ".innerhtml", "atob("]
        smuggling_score = sum(3 for pattern in smuggling_keywords if pattern in text_lower)
        
        if smuggling_score > 0:
            # Force high NLP threat
            nlp_prob = min(1.0, (smuggling_score * 0.3) + 0.6)
        elif text_model and vectorizer and text_content:
            X_vec = vectorizer.transform([text_content])
            nlp_prob = float(text_model.predict_proba(X_vec)[0][1])
        else:
            suspicious_keywords = ["urgent", "password", "verify", "suspended", "account", "compromised", "click here"]
            score = sum(1 for word in suspicious_keywords if word in text_lower) * 0.2
            nlp_prob = min(1.0, score)

        # 2. Attachments & Sender
        attachment_risk = sandbox_analyze_attachments(data.attachments or [])
        sender_risk = osint_check_sender(data.sender or "")

        # 3. URL Analysis
        url_risk = analyze_links(data.links or [])
        
        # We need a robust combined score. Text alone should RARELY trigger a classification without suspicious links or sender.
        # NLP score gets dampened if the sender is definitively known and URLs are safe.
        
        base_risk = (nlp_prob * 0.35) + (attachment_risk * 0.35) + max(0, sender_risk) * 0.15 + (url_risk * 0.5)
        
        # If sender is explicitly verified safe and link is safe, dampen the NLP alarm significantly
        if sender_risk < 0 and url_risk < 0.2:
            base_risk -= 0.3

        # Severe Threat Overrides:
        if url_risk > 0.75:
            base_risk = max(base_risk, 0.90)
        elif sender_risk > 0.5:
            base_risk = max(base_risk, 0.85)
        elif smuggling_score > 0:
            base_risk = max(base_risk, 0.95)
        elif attachment_risk >= 0.4:
            base_risk = max(base_risk, 0.85)

        final_prob = max(0.0, min(1.0, base_risk))

        label = "phishing" if final_prob > 0.5 else "legitimate"
        
        return {
            "label": label, 
            "probability": round(final_prob, 3),
            "details": {
                "nlp_score": round(nlp_prob, 3),
                "attachment_risk": round(attachment_risk, 3),
                "sender_risk": round(sender_risk, 3),
                "url_risk": round(url_risk, 3)
            }
        }

    except Exception as e:
        return {"error": str(e)}

@app.get("/")
def home():
    return {"message": "PhishiFy API is running (Advanced NLP + Heuristics Model)"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
