*** Download CEAS_08.csv datasets from Kaggle for AI Training

# 📧 Gmail Phishing Detector (AI + Rule-Based)

This project is a **Gmail-inspired phishing email detector** built with **Python**, **Tkinter**, and **Machine Learning (Logistic Regression)**. It combines AI and rule-based detection to simulate an interactive email viewer that helps users identify and manage phishing emails.

---

## 🚀 Features

✅ **AI Detection:**
Trained using a TF-IDF vectorizer and logistic regression model on a real phishing dataset.

✅ **Rule-Based Detection:**
Checks for known phishing patterns like suspicious domains, urgent language, generic greetings, and more (12 indicators).

✅ **Interactive UI:**

* Gmail-style interface with folders (Inbox, Spam, Trash, Blocked)
* Email viewer with "Safe" or "Phishing" alerts
* Action buttons: Mark as Spam, Delete, Block, Preview
* Sort emails A-Z or Z-A

✅ **Logging & Analysis:**

* Logs detection results into `phishing_log.csv`
* Saves confusion matrix and accuracy charts for reference
* Easy retraining and model update using `train_model.py`

---

## 🧠 How the AI Works

The ML model was trained using:

* `CEAS_08.csv` dataset with labeled phishing and legitimate emails.
* Preprocessing: Lowercasing, URL and punctuation removal.
* TF-IDF vectorization (bigrams, stopword removal, min/max thresholds).
* Logistic Regression classifier (max\_iter=1000).
* Accuracy reports and confusion matrix are auto-generated.

---

## 🛠 Installation

1. Clone the repo:

```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
```

2. Install required packages:

```bash
pip install -r requirements.txt
```

3. Make sure you have:

   * `phishing_and_legit_mixed.json` for sample emails.
   * Trained model files: `phishing_model.pkl` and `vectorizer.pkl` (or run the training script below).

---

## 🧪 Train Your Own Model

Use the script `train_model.py` to train or retrain the model:

```bash
python train_model.py
```

This will:

* Load the dataset
* Clean and vectorize the text
* Train the Logistic Regression model
* Save the model and vectorizer files
* Generate and save evaluation metrics (`accuracy_comparison.png`, `confusion_matrix.png`)

---

## ▶️ Run the App

Once everything is set up, launch the email detection app:

```bash
python phishing_detector_gui.py
```

You can now browse and analyze emails interactively!

---

## 📂 Folder Structure

```
📁 phishing-detector/
├── phishing_detector_gui.py   # Main GUI application
├── train_model.py             # Model training script
├── phishing_model.pkl         # Trained ML model
├── vectorizer.pkl             # TF-IDF vectorizer
├── phishing_and_legit_mixed.json  # Sample emails
├── phishing_log.csv           # Output log file
├── accuracy_comparison.png    # Training vs Test accuracy chart
├── confusion_matrix.png       # Confusion matrix heatmap
└── README.md                  # You are here
```

---

## 📌 Disclaimer

This is a simulation project for educational and awareness purposes. It does **not** connect to real Gmail accounts or access any live inboxes.

