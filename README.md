# PassSentinel
PassSentinel is an advanced browser-based cybersecurity tool built with pure HTML, CSS, and JavaScript. It analyzes password strength, calculates entropy, provides actionable feedback, generates secure passwords, and securely hashes input using the Web Crypto API — all locally in your browser.

---

## 🧠 Features

- ✅ **Password Strength Analysis**
  - Real-time entropy and heuristic scoring  
  - Animated strength meter and colour feedback  
  - Actionable suggestions for improvement  

- 🧮 **Entropy Calculation**
  - Estimates password entropy (bits of randomness)
  - Uses mathematical modelling for real security metrics  

- 🔑 **Password Generator**
  - Customizable length (8–64)
  - Toggle lowercase, uppercase, numbers, and symbols  
  - Copy to clipboard instantly  

- 🧰 **Security Tools**
  - SHA-256 hash preview using Web Crypto API  
  - Quick local breach check (demo list)  
  - Copy, paste, and clear controls  

- 🧱 **Local History & Export**
  - Save analysed passwords with entropy and scores  
  - Stored securely in `localStorage` (browser only)  
  - Export to CSV or clear history anytime  

- 🌙 **Theme Toggle**
  - Elegant light/dark mode  
  - Modern, glassy dark UI built with CSS gradients and animations  

---

## 🖥️ Tech Stack

| Technology | Purpose |
|-------------|----------|
| **HTML5** | Structure & accessibility |
| **CSS3** | Modern UI with gradients and animations |
| **JavaScript (ES6+)** | Core logic and interactivity |
| **Web Crypto API** | Secure hash generation |
| **localStorage API** | Local password history storage |

---

## 🧩 Folder Structure

PassSentinel/
├── index.html # Main HTML file
├── style.css # All visual styling
├── app.js # Application logic
└── README.md # Project documentation


---

## 🚀 Getting Started

### 1️⃣ Clone this repository
```bash
git clone https://github.com/KALPESH003/PassSentinel.git
###2️⃣Open the project
###3️⃣ Run the project
Just open index.html directly in your browser — no setup or dependencies required.
