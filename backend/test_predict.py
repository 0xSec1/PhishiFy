import requests
import json
import time

API_URL = "http://127.0.0.1:5000/predict_email"

test_cases = [
    {
        "name": "1. Benign / Safe Email",
        "payload": {
            "sender": "no-reply@google.com",
            "subject": "New sign-in from Chrome on Windows",
            "bodyText": "Your Google Account was just signed in to from a new Windows device. You're getting this email to make sure it was you. If this was you, then you don't have to do anything.",
            "links": [{"url": "https://myaccount.google.com/notifications"}],
            "attachments": []
        }
    },
    {
        "name": "2. Classic Phishing (Urgent, Bad Domain)",
        "payload": {
            "sender": "sec-alert-service@yahoo-update-123.com",
            "subject": "URGENT: Your account has been suspended",
            "bodyText": "Dear user, your account has been compromised. Please click here to verify your identity and restore access.",
            "links": [{"url": "http://verify-account-update.xyz/login.php"}],
            "attachments": []
        }
    },
    {
        "name": "3. Spear Phishing (DocuSign Fake Invoice)",
        "payload": {
            "sender": "e-signature@docusign-auth-secure.com",
            "subject": "Review and Sign: Invoice INV-99321",
            "bodyText": "Please review and electronically sign the attached invoice document. This link will expire in 24 hours.",
            "links": [{"url": "https://secure-document-portal.net/docusign/INV-99321"}],
            "attachments": []
        }
    },
    {
        "name": "4. Malware Attachment (No malicious text/links)",
        "payload": {
            "sender": "hr@partner-company.com",
            "subject": "Requested Candidate Resumes",
            "bodyText": "Hi team, please find the candidate resumes attached for the upcoming interviews.",
            "links": [],
            "attachments": [{"name": "candidate_resume.exe"}, {"name": "portfolio.pdf"}]
        }
    },
    {
        "name": "5. HTML Smuggling / Dynamic DOM Payload",
        "payload": {
            "sender": "secure-delivery@trusted-system.com",
            "subject": "Encrypted Message Delivery",
            "bodyText": "<!DOCTYPE html><html><body><p>Review the attached encrypted secure document.</p><svg width=\"1\" height=\"1\" xmlns=\"http://www.w3.org/2000/svg\"><script type=\"text/javascript\">const fragments = ['ht', 'tps:', '/', '/da', 'rk', 'net', '-i', 'nfr', 'a.c', 'om/']; let a = document.createElement('a'); a.textContent = \"Click to Decrypt Document\"; a.href = fragments.join(''); a.className = \"secure-btn btn-primary\"; window.onload = function() { document.body.appendChild(a); }; </script></svg></body></html>",
            "links": [],
            "attachments": [{"name": "encrypted_document.html"}]
        }
    },
    {
        "name": "6. Known Bad Sender Heuristic",
        "payload": {
            "sender": "fake-support@paypal-auth.com",
            "subject": "Account Review",
            "bodyText": "Just a standard account review. Nothing else.",
            "links": [{"url": "https://google.com"}],
            "attachments": []
        }
    }
]

print(f"Connecting to {API_URL}...\n")

for i, test in enumerate(test_cases):
    print(f"--- Running Test: {test['name']} ---")
    try:
        res = requests.post(API_URL, json=test["payload"])
        if res.status_code == 200:
            data = res.json()
            label = data.get("label", "unknown").upper()
            prob = data.get("probability", 0.0)
            details = data.get("details", {})
            print(f"Result: {label} (Confidence: {prob})")
            print(f"Details: {json.dumps(details, indent=2)}")
        else:
            print(f"Error: Server returned status code {res.status_code}")
    except Exception as e:
        print(f"Error connecting to backend: {e}")
    
    print("\n" + "="*50 + "\n")
    time.sleep(0.5)

print("Testing complete.")
