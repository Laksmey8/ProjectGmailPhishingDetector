# === 📦 IMPORTS ===
import tkinter as tk
from tkinter import messagebox
import joblib
import re
import csv
import os
from datetime import datetime
import json
from urllib.parse import urlparse

# === 📂 DATA & MODEL LOADING ===
with open("phishing_and_legit_mixed.json") as f:
   email_samples = json.load(f)

inbox_emails = email_samples.copy()
spam_emails = []
trash_emails = []
blocked_emails = []

try:
   model = joblib.load("phishing_model.pkl")
   vectorizer = joblib.load("vectorizer.pkl")
except Exception as e:
   messagebox.showerror("Error", f"Failed to load model or vectorizer: {e}")
   inbox.destroy()

# === 🧠 RULE-BASED ANALYSIS ===
def analyze_email(email):
   score = 0
   reasons = []


   if not re.match(r".+@(gmail|netflix|bank|university|trustedsource|company)\.com$", email["sender"]):
       score += 1
       reasons.append("Sender email domain looks unfamiliar.")


   if re.search(r"suspend|immediate|urgent|verify|reset", email["subject"], re.IGNORECASE):
       score += 1
       reasons.append("Subject sounds urgent or threatening.")


   if re.search(r"dear user|dear customer|hello customer", email["body"], re.IGNORECASE):
       score += 1
       reasons.append("Uses generic greeting instead of your name.")


   if re.search(r"\b[a-z]{1,3}\b", email["body"]) or not re.search(r"\.", email["body"]):
       score += 1
       reasons.append("Text may contain grammar or spelling issues.")

   if any(att.endswith((".exe", ".zip", ".html", ".pdf")) for att in email["attachments"]):
       score += 1
       reasons.append("Email has uncommon or potentially unsafe attachments.")

   if re.search(r"password|credit card|2FA|verification code", email["body"], re.IGNORECASE):
       score += 1
       reasons.append("Requests sensitive information.")

   if "google" in email["body"].lower() and "gmail.com" not in email["sender"]:
       score += 1
       reasons.append("Mentions Google, but sender isn't from gmail.com.")


   if email["sender"] != email["reply_to"]:
       score += 1
       reasons.append("Sender and reply-to addresses don't match.")

   if re.search(r"won|free|gift|macbook", email["body"], re.IGNORECASE):
       score += 1
       reasons.append("Mentions prizes or offers that sound too good to be true.")

   if re.search(r"[A-Z]{2,}", email["body"]) or re.search(r"\n{2,}", email["body"]):
       score += 1
       reasons.append("Unusual formatting used in the message.")

   if "seems dangerous" in email["body"].lower():
       score += 1
       reasons.append("This message may be flagged by Gmail.")

   urls = re.findall(r"http[s]?://\S+", email["body"])
   for url in urls:
       parsed = urlparse(url)
       domain = parsed.netloc.lower()

       if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
           score += 1
           reasons.append(f"Link uses raw IP address: {domain}")
           break


       if domain.endswith((".xyz", ".ru", ".cn", ".tk", ".info", ".biz")):
           score += 1
           reasons.append(f"Suspicious top-level domain: {domain}")
           break

       if domain.count(".") > 3:
           score += 1
           reasons.append(f"Too many subdomains in URL: {domain}")
           break
           
       if "google" in domain and not domain.endswith("google.com"):
           score += 1
           reasons.append(f"Impersonating Google with fake domain: {domain}")
           break


   return score, reasons


# === 📁 LOGGING ===
def log_result(email, ai_score, rule_score, result):
   file_exists = os.path.isfile("phishing_log.csv")
   with open("phishing_log.csv", mode="a", newline="", encoding="utf-8") as file:
       writer = csv.writer(file)
       if not file_exists:
           writer.writerow(["Timestamp", "Sender", "Subject", "AI Score", "Rule Score", "Result"])
       writer.writerow([
           datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
           email["sender"],
           email["subject"],
           f"{ai_score:.2%}",
           rule_score,
           result
       ])


# === 🧩 SCROLL UTILITY ===
def create_scrollable_frame(container):
   canvas = tk.Canvas(container, bg=container["bg"])
   scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
   scroll_frame = tk.Frame(canvas, bg=container["bg"])
   scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
   canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
   canvas.configure(yscrollcommand=scrollbar.set)
   canvas.pack(side="left", fill="both", expand=True)
   scrollbar.pack(side="right", fill="y")
   return scroll_frame


# === EMAIL VIEWERS ===
def show_safe_viewer(email, ai_confidence):
   reader = tk.Toplevel()
   reader.title("📨 Safe Email Viewer")
   reader.geometry("600x400")
   reader.configure(bg="white")
   tk.Label(reader, text="✅ This email is safe", font=("Arial", 16, "bold"), fg="green", bg="white").pack(pady=(10, 5))
   label = "High confidence this is safe!" if ai_confidence < 0.5 else "Likely safe, but stay aware!"
   tk.Label(reader, text=label, font=("Arial", 10), fg="gray", bg="white").pack()
   tk.Label(reader, text="Subject: " + email["subject"], font=("Arial", 12, "bold"), bg="white", wraplength=580, justify="left").pack(pady=(15, 5), padx=10, anchor="w")
   body = tk.Text(reader, wrap="word", font=("Arial", 11), bg="#f7f7f7", fg="black")
   body.insert("1.0", email["body"])
   body.config(state="disabled")
   body.pack(padx=10, pady=5, fill="both", expand=True)


def show_popup(email, reasons, ai_confidence, rule_score, index):
   popup = tk.Toplevel()
   popup.title("Phishing Alert")
   popup.geometry("360x520")
   popup.configure(bg="black")
   canvas = tk.Canvas(popup, width=80, height=80, bg="black", highlightthickness=0)
   canvas.pack(pady=(30, 0))
   canvas.create_polygon(10, 10, 70, 10, 70, 70, 10, 70, fill="blue", outline="blue")
   canvas.create_text(40, 40, text="</>", fill="white", font=("Arial", 14, "bold"))
   tk.Label(popup, text="WARNING!", font=("Arial", 18, "bold"), fg="red", bg="black").pack(pady=(10, 5))
   mid_frame = tk.Frame(popup, bg="black")
   mid_frame.pack(pady=(5, 10))
   tk.Label(mid_frame, text=f"⚠️ Estimated Risk: {ai_confidence:.2%}", font=("Arial", 10), bg="black", fg="yellow").pack()
   tk.Label(mid_frame, text=f"🛡 Phishing Clues Found: {rule_score}/12", font=("Arial", 10), bg="black", fg="lightblue").pack()
   tk.Label(popup, text="\n- " + "\n- ".join(reasons), font=("Arial", 10), bg="black", fg="white", justify="left", wraplength=280).pack(pady=5)
   btn_style = {"font": ("Arial", 10, "bold"), "fg": "black", "bg": "blue", "activebackground": "#0011aa", "bd": 0, "width": 25, "height": 2}
   tk.Button(popup, text="📤 Mark as Spam", command=lambda: move_to_spam(index, popup), **btn_style).pack(pady=5)
   tk.Button(popup, text="🗑 Delete Email", command=lambda: delete_email(index, popup), **btn_style).pack(pady=5)
   tk.Button(popup, text="🚫 Block Sender", command=lambda: move_to_block(index, popup), **btn_style).pack(pady=5)
   tk.Button(popup, text="👀 Preview Email", command=lambda: show_phishing_viewer(email), **btn_style).pack(pady=5)


# === CHECK EMAIL ===
def check_email(index):
    if current_folder == "Inbox":
        email = inbox_emails[index]
        content = f"{email['subject']}\n{email['body']}"
        features = vectorizer.transform([content])
        ai_prediction = model.predict(features)[0]
        ai_confidence = model.predict_proba(features)[0][1]
        rule_score, reasons = analyze_email(email)
        result = "Phishing" if rule_score >= 4 or ai_prediction == 1 else "Safe"
        log_result(email, ai_confidence, rule_score, result)
        if result == "Phishing":
            show_popup(email, reasons, ai_confidence, rule_score, index)
        else:
            show_safe_viewer(email, ai_confidence)

    else:
        # If in Spam, Trash, or Blocked, directly open the preview safely without popup
        if current_folder == "Spam":
            email = spam_emails[index]
        elif current_folder == "Trash":
            email = trash_emails[index]
        elif current_folder == "Blocked":
            email = blocked_emails_stack.stack[index]

        show_phishing_viewer(email)


def delete_email(index, popup):
    if current_folder == "Inbox":
        trash_emails.append(inbox_emails.pop(index))
    elif current_folder == "Spam":
        trash_emails.append(spam_emails.pop(index))
    refresh_email_lists()
    if popup:
        popup.destroy()


def move_to_spam(index, popup):
    if current_folder == "Inbox":
        spam_emails.append(inbox_emails.pop(index))
    refresh_email_lists()
    if popup:
        popup.destroy()


class EmailStack:
    def __init__(self):
        self.stack = []

    def push(self, item):
        self.stack.append(item)

    def pop(self):
        if not self.is_empty():
            return self.stack.pop()

    def is_empty(self):
        return len(self.stack) == 0

blocked_emails_stack = EmailStack()


def move_to_block(index, popup):
    if current_folder == "Inbox":
        blocked_emails_stack.push(inbox_emails.pop(index))
    elif current_folder == "Spam":
        blocked_emails_stack.push(spam_emails.pop(index))
    elif current_folder == "Trash":
        blocked_emails_stack.push(trash_emails.pop(index))
    refresh_email_lists()
    if popup:
        popup.destroy()

def bubble_sort(emails, ascending=True):
    n = len(emails)
    for i in range(n):
        for j in range(0, n-i-1):
            if (ascending and emails[j]['sender'].lower() > emails[j+1]['sender'].lower()) or \
               (not ascending and emails[j]['sender'].lower() < emails[j+1]['sender'].lower()):
                emails[j], emails[j+1] = emails[j+1], emails[j]
    return emails

def switch_folder(folder_name):
    global current_folder, sort_mode_enabled
    current_folder = folder_name

    # Update counts
    inbox_button_text.set(f"📥 Inbox ({len(inbox_emails)})")
    spam_button_text.set(f"⚠️ Spam ({len(spam_emails)})")
    trash_button_text.set(f"🗑 Trash ({len(trash_emails)})")
    blocked_button_text.set(f"🚫 Blocked ({len(blocked_emails_stack.stack)})")

    if current_folder == "Inbox":
        sort_mode_enabled = False
        header_title.config(text=f"📧 Gmail Phishing Detector — Inbox ({len(inbox_emails)})")
        inbox_panel_title.config(text=f"Inbox ({len(inbox_emails)})")
    elif current_folder == "Spam":
        header_title.config(text=f"📧 Gmail Phishing Detector — Spam ({len(spam_emails)})")
        inbox_panel_title.config(text=f"Spam ({len(spam_emails)})")
    elif current_folder == "Trash":
        header_title.config(text=f"📧 Gmail Phishing Detector — Trash ({len(trash_emails)})")
        inbox_panel_title.config(text=f"Trash ({len(trash_emails)})")
    elif current_folder == "Blocked":
        header_title.config(text=f"📧 Gmail Phishing Detector — Blocked ({len(blocked_emails_stack.stack)})")
        inbox_panel_title.config(text=f"Blocked ({len(blocked_emails_stack.stack)})")

    refresh_email_lists()


# === 👀 PHISHING EMAIL PREVIEW VIEWER ===
def show_phishing_viewer(email):
   reader = tk.Toplevel()
   reader.title("⚠️ Phishing Email Preview")
   reader.geometry("600x400")
   reader.configure(bg="white")
   tk.Label(reader, text="⚠️ Warning: Phishing Email", font=("Arial", 16, "bold"), fg="red", bg="white").pack(pady=(10, 5))
   tk.Label(reader, text="Please be careful with this email content.", font=("Arial", 10), fg="gray", bg="white").pack()
   tk.Label(reader, text="Subject: " + email["subject"], font=("Arial", 12, "bold"), bg="white", wraplength=580, justify="left").pack(pady=(15, 5), padx=10, anchor="w")
   body = tk.Text(reader, wrap="word", font=("Arial", 11), bg="#fff0f0", fg="black")
   body.insert("1.0", email["body"])
   body.config(state="disabled")
   body.pack(padx=10, pady=5, fill="both", expand=True)
# === GUI START ===
inbox = tk.Tk()
inbox.title("📧 Gmail Phishing Detector — 100 Emails")
inbox.geometry("1080x720")
inbox.configure(bg="white")

# === 🧩 HEADER ===
header = tk.Frame(inbox, bg="#f1f3f4", height=60)
header.pack(fill="x", side="top")

header_title = tk.Label(
    header,
    text="📧 Gmail Phishing Detector — Inbox",
    font=("Segoe UI", 20, "bold"),
    fg="#202124",
    bg="#f1f3f4",
    padx=30
)
header_title.pack(pady=10)

# === 🧱 MAIN CONTAINER ===
main_frame = tk.Frame(inbox, bg="white")
main_frame.pack(fill="both", expand=True, pady=(0, 10))
# === 📁 SIDEBAR ===
sidebar = tk.Frame(main_frame, bg="#ffffff", width=200)
sidebar.pack(side="left", fill="y")
# StringVars for dynamic button text
inbox_button_text = tk.StringVar()
spam_button_text = tk.StringVar()
trash_button_text = tk.StringVar()
blocked_button_text = tk.StringVar()
tk.Label(
   sidebar,
   text="Folders",
   font=("Segoe UI", 11, "bold"),
   bg="white",
   fg="#5f6368",
   padx=20
).pack(anchor="w", pady=(15, 5))
folder_btn_style = {
   "font": ("Segoe UI", 12),
   "bg": "white",
   "relief": "flat",
   "anchor": "w",
   "padx": 25,
   "width": 20
}
tk.Button(sidebar, textvariable=inbox_button_text, fg="#1a73e8", command=lambda: switch_folder("Inbox"), **folder_btn_style).pack(fill="x", pady=2)
tk.Button(sidebar, textvariable=spam_button_text, fg="#d93025", command=lambda: switch_folder("Spam"), **folder_btn_style).pack(fill="x", pady=2)
tk.Button(sidebar, textvariable=trash_button_text, fg="#5f6368", command=lambda: switch_folder("Trash"), **folder_btn_style).pack(fill="x", pady=2)
tk.Button(sidebar, textvariable=blocked_button_text, fg="#000000", command=lambda: switch_folder("Blocked"), **folder_btn_style).pack(fill="x", pady=2)
# Sort options
tk.Label(
    sidebar,
    text="Sort Options",
    font=("Segoe UI", 11, "bold"),
    bg="white",
    fg="#5f6368",
    padx=20
).pack(anchor="w", pady=(20, 5))

sort_btn_style = {
    "font": ("Segoe UI", 11),
    "bg": "#e8f0fe",
    "relief": "flat",
    "anchor": "w",
    "padx": 25,
    "width": 20
}

def sort_az():
    global sort_ascending, sort_mode_enabled
    sort_ascending = True
    sort_mode_enabled = True
    refresh_email_lists()

def sort_za():
    global sort_ascending, sort_mode_enabled
    sort_ascending = False
    sort_mode_enabled = True
    refresh_email_lists()

tk.Button(sidebar, text="🔼 Sort A-Z", fg="#1a73e8", command=sort_az, **sort_btn_style).pack(fill="x", pady=2)
tk.Button(sidebar, text="🔽 Sort Z-A", fg="#d93025", command=sort_za, **sort_btn_style).pack(fill="x", pady=2)

# === 📦 CONTENT FRAME ===
content_frame = tk.Frame(main_frame, bg="#f8f9fa")
content_frame.pack(side="left", fill="both", expand=True, padx=(10, 20))
# === ✉️ INBOX PANEL ===
inbox_panel = tk.LabelFrame(
    content_frame,
    font=("Segoe UI", 11, "bold"),
    fg="#202124",
    bg="white",
    padx=10,
    pady=10,
    bd=1,
    relief="solid",
    labelanchor="n"
)
inbox_panel.pack(fill="both", expand=True, padx=10, pady=10)

# Create a dynamic title variable
inbox_panel_title = tk.Label(
    inbox_panel,
    text="Inbox",
    font=("Segoe UI", 14, "bold"),
    bg="white",
    fg="#5f6368",
)
inbox_panel_title.pack(pady=(0, 5))

inbox_list = create_scrollable_frame(inbox_panel)
# === 🔄 REFRESH EMAILS ===
sort_ascending = True
sort_mode_enabled = False

def refresh_email_lists():
    try:
        for widget in inbox_list.winfo_children():
            widget.destroy()

        # ✨ ADD THIS BLOCK HERE ✨
        inbox_button_text.set(f"📥 Inbox ({len(inbox_emails)})")
        spam_button_text.set(f"⚠️ Spam ({len(spam_emails)})")
        trash_button_text.set(f"🗑 Trash ({len(trash_emails)})")
        blocked_button_text.set(f"🚫 Blocked ({len(blocked_emails_stack.stack)})")

        # Then continue loading emails
        if current_folder == "Inbox":
            emails_to_show = inbox_emails.copy()
            if sort_mode_enabled:
                emails_to_show = sorted(
                    emails_to_show, key=lambda email: email.get('sender', '').lower(), reverse=not sort_ascending
                )
        elif current_folder == "Spam":
            emails_to_show = bubble_sort(spam_emails.copy(), ascending=sort_ascending)
        elif current_folder == "Trash":
            emails_to_show = bubble_sort(trash_emails.copy(), ascending=sort_ascending)
        elif current_folder == "Blocked":
            emails_to_show = bubble_sort(blocked_emails_stack.stack.copy(), ascending=sort_ascending)
        else:
            emails_to_show = []

        # Display emails
        for i, email in enumerate(emails_to_show):
            sender = email.get("sender", "Unknown Sender")
            subject = email.get("subject", "No Subject")
            display_text = f"{sender} — {subject}"
            btn = tk.Button(
                inbox_list,
                text=display_text,
                font=("Segoe UI", 10),
                width=95,
                anchor="w",
                padx=10,
                pady=6,
                relief="flat",
                bg="white",
                activebackground="#e8f0fe",
                cursor="hand2",
                command=lambda i=i: check_email(i)
            )
            btn.pack(fill="x", pady=2)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to refresh emails: {e}")

# === 📌 SET DEFAULT FOLDER ===
sort_ascending = True  # Default A-Z
current_folder = "Inbox"
refresh_email_lists()
# === 🖥️ LAUNCH APP ===
inbox.mainloop()
