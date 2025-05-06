import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import joblib


# === STEP 1: Load Dataset (using correct columns) ===
df = pd.read_csv("/Users/chhoethchanrithlaksmey/Downloads/CEAS_08.csv")
df = df[["body", "label"]].dropna()
df.columns = ["content", "label"]  # Rename for consistency


# === STEP 2: Clean Text ===
def clean_text(text):
   text = str(text).lower()
   text = re.sub(r"http\S+", "", text)  # Remove URLs
   text = re.sub(r"[^a-z\s]", "", text)  # Remove punctuation/numbers
   return text


df["content"] = df["content"].apply(clean_text)


# === STEP 3: Vectorization (TF-IDF) ===
vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english", max_df=0.9, min_df=5)
X = vectorizer.fit_transform(df["content"])
y = df["label"]


# === STEP 4: Train/Test Split ===
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.3, random_state=42)


# === STEP 5: Model Training ===
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)


# === STEP 6: Evaluation ===
y_pred = model.predict(X_test)


test_accuracy = accuracy_score(y_test, y_pred)
train_accuracy = model.score(X_train, y_train)


print("Test Accuracy:", test_accuracy)
print("Training Accuracy:", train_accuracy)
print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# === STEP 7: Confusion Matrix ===
conf_matrix = confusion_matrix(y_test, y_pred)
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=["Safe", "Phishing"], yticklabels=["Safe", "Phishing"])
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig("confusion_matrix.png")
plt.close()


# === STEP 8: Compare Test vs Training Accuracy ===
plt.figure(figsize=(6, 4))
accuracies = [train_accuracy, test_accuracy]
labels = ["Training Accuracy", "Test Accuracy"]
colors = ["skyblue", "lightgreen"]


# Draw the bars
bars = plt.bar(labels, accuracies, color=colors)
plt.ylim(0, 1.05)  # slightly higher limit to avoid overlap
plt.title("Training vs Test Accuracy Comparison", pad=20)  # move title up using pad
plt.ylabel("Accura cy")
plt.grid(axis='y', linestyle='--', alpha=0.7)


# Add accuracy values on top of the bars
for index, value in enumerate(accuracies):
   plt.text(index, value + 0.005, f"{value:.4f}", ha='center', va='bottom', fontweight='bold')


plt.tight_layout()
plt.savefig("accuracy_comparison.png")
plt.show()


# === STEP 9: Save Model & Vectorizer ===
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")


