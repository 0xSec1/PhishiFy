import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report

print("Loading dataset...")
try:
    df = pd.read_csv("data/emails.csv", usecols=["message"], nrows=15000)
except Exception as e:
    print(f"Error loading CSV: {e}")
    df = pd.DataFrame({"message": []})

def extract_body(raw_message):
    if not isinstance(raw_message, str):
        return ""
    parts = raw_message.split("\n\n", 1)
    if len(parts) > 1:
        return parts[1].strip()
    return raw_message.strip()

# Add extra phishing examples to ensure the model learns malicious intent
phishing_examples = [
    "Your account has been compromised please click on this link click here.",
    "URGENT: Verify your Google account immediately or it will be suspended.",
    "You have a new secure message from your bank. Login to view.",
    "Click here to claim your $1000 prize.",
    "Update your billing information to avoid service interruption.",
    "Important security alert regarding your recent sign-in.",
    "Your password expires in 24 hours. Change it now."
]
safe_examples = [
    "Hi there, just checking in about our meeting tomorrow.",
    "Here is the monthly report you asked for.",
    "Let's grab lunch at 12.",
    "Attached is the documentation for the new project.",
    "Can we reschedule our call to next week?"
]

extra_df = pd.DataFrame({
    "message": phishing_examples + safe_examples,
    "label": [1]*len(phishing_examples) + [0]*len(safe_examples)
})

if not df.empty:
    df["bodyText"] = df["message"].apply(extract_body)
    def simulate_label(text):
        text = str(text).lower()
        phish_keywords = ["urgent", "password", "verify", "suspended", "account", "invoice", "bank", "login", "compromised", "click here", "security alert"]
        score = sum(1 for w in phish_keywords if w in text)
        return 1 if score > 0 else 0
    df["label"] = df["bodyText"].apply(simulate_label)
    df = pd.concat([df[["bodyText", "label"]], extra_df.rename(columns={"message": "bodyText"})], ignore_index=True)
else:
    extra_df["bodyText"] = extra_df["message"]
    df = extra_df

print("Vectorizing Text...", len(df), "samples")
X_text = df["bodyText"].fillna("")
y = df["label"]

vectorizer = TfidfVectorizer(max_features=2000, stop_words='english', ngram_range=(1,2))
X_vec = vectorizer.fit_transform(X_text)

X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

# Using a powerful Gradient Boosting model instead of Random Forest
print("Training Gradient Boosting model (XGBoost logic)...")
model = GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, max_depth=5, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\nClassification Report:\n", classification_report(y_test, y_pred))

os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/phish_text_model.joblib")
joblib.dump(vectorizer, "model/tfidf_vectorizer.joblib")
print("✅ Advanced NLP Model (Gradient Boosting) & Vectorizer saved.")
