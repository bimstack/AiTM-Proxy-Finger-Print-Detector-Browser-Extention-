# AiTM Proxy Fingerprint Detector: User Guide

Welcome! If you're reading this, you've taken a fantastic step toward securing your online accounts. This guide is designed to explain what the **AiTM Proxy Fingerprint Detector** is, how it works, and how to use it—all in plain, simple English. No tech jargon, we promise!

---

## Table of Contents
1. [What is this?](#what-is-this)
2. [How does it protect you?](#how-does-it-protect-you)
3. [What do the alerts mean?](#what-do-the-alerts-mean)
4. [How to install it](#how-to-install-it)
5. [How to use it](#how-to-use-it)
6. [What to do if you see a warning](#what-to-do-if-you-see-a-warning)
7. [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
8. [Why this matters](#why-this-matters)

---

## What is this?

Imagine you're going to your bank. The building looks real, the tellers look real, and the sign outside says the right name. But what if the walls were actually made of cardboard, the vault was just an empty box, and the address was slightly off? 

In the digital world, criminals can do exactly this. There is a type of cyber attack where scammers create fake, identical copies of login pages for services like Microsoft, Google, or your bank. These fake pages look completely real. 

When you type your password into one of these fake pages, it goes straight to the criminal. What's worse, the criminal's fake page immediately logs into the *real* site at the same time. If your account asks for a two-factor authentication code (like a text message or a prompt on your authenticator app), the fake page asks you for it too. You enter it, the criminal uses it on the real site, and just like that, they've stolen your login session. 

**This extension is like a brilliant security guard.** It stands by while you browse and constantly checks if the login page you are on is actually the real deal, or a cleverly disguised fake. It checks all the little things that are incredibly hard for scammers to fake perfectly.

---

## How does it protect you?

Our security guard uses five clever detection methods to spot a fake website. Here is what it checks behind the scenes:

### 1. Checking the Address (URL Analysis)
Is the website address suspicious? Just like you'd be suspicious if your bank's address had extra words tacked on (like "bankofamerica-secure-login.com" instead of just "bankofamerica.com"), the extension checks for weirdly long or deceptive addresses.

### 2. Checking the Paperwork (Security Headers)
Does the website send the right security documents? When a browser talks to a legitimate website, the website sends along invisible "paperwork" that proves it is secure. A fake, intercepted site often messes this paperwork up. This is like checking if a store has the correct permits and licenses displayed on the wall.

### 3. Checking the Appearance (Visual Spoofing)
Does the page look exactly like a Microsoft or Google page, but isn't actually on their website? If you walked into a shop with a McDonald's sign but it was operating out of someone's garage, you'd know something was wrong. The extension does the same thing for web pages.

### 4. Checking the Speed (Timing Fingerprints)
Is the website responding strangely slowly? When a criminal intercepts your connection, everything takes just a tiny bit longer because the traffic has to pass through their hidden systems first. It's like calling your friend, but it takes 5 seconds to connect—you might wonder if someone is listening in the middle. The extension measures these tiny delays.

### 5. Checking the Reputation (Domain Age & Popularity)
Is this website brand new and registered on a cheap or suspicious domain? Legitimate companies have owned their website names for years. Scammers often set up brand new websites that have zero reputation. It's like walking into a brand new store that has no reviews and no history.

---

## What do the alerts mean?

The extension keeps things simple by giving you a color-coded traffic light system. Here is what each color means:

### 🟢 SAFE (Green)
**Everything looks normal.** No signs of interception detected. The security guard has checked the building, and it looks exactly like it should. You can confidently enter your password.

### 🟡 SUSPICIOUS (Yellow/Amber)
**Something looks a bit off.** The extension found some unusual signals. It might be nothing—sometimes legitimate websites have weird setups—but you should be cautious. **Don't enter sensitive information** until you verify that you are absolutely on the correct website. 

### 🔴 DANGEROUS (Red)
**Multiple strong indicators that this is a fake or intercepted site.** The security guard has found cardboard walls and a fake vault. **Do NOT enter your password.** Close the tab immediately and report it to your IT team if you are at work.

---

## How to install it

Installing the extension takes just a minute. Follow these simple steps:

1. **Download** the extension folder to your computer (and unzip/extract it if it's in a .zip file).
2. **Open Chrome**, and in the address bar at the top, type exactly this and press Enter: `chrome://extensions`
3. In the top right corner of that page, turn on the toggle switch for **Developer mode**.
4. A new menu bar will appear at the top left. Click the button that says **Load unpacked**.
5. **Select the AiTM folder** you downloaded in step 1.
6. **You're done!** The shield icon will now appear in your browser toolbar (you may need to click the puzzle piece icon to pin the shield so it's always visible).

---

## How to use it

Using the AiTM Proxy Fingerprint Detector is effortless because it does the hard work for you automatically!

- **Watch the Shield:** The shield icon in your browser toolbar will change color (Green, Yellow, or Red) based on the threat level of the page you are currently viewing.
- **Click for Details:** Anytime you want more information, just click the shield icon. A small window will pop open showing you the details about the current page.
- **Understand the Score:** In that window, you'll see a Threat Score from 0 to 100. A low score is great! A high score means danger. You'll also see a clear breakdown of exactly what the extension checked and what it found.
- **Read the Warnings:** If you see any warnings, simply read the details provided. They will explain exactly what looked suspicious.

---

## What to do if you see a warning

First of all: **Don't panic!** The tool is designed to be very sensitive, so occasionally, a completely legitimate website might trigger a minor warning. Here is how you should handle alerts:

- **If it says 🔴 DANGEROUS:** 
  - **Do NOT enter any passwords.**
  - Close the browser tab immediately.
  - If this happened on a work computer, report it to your IT security team right away.
  
- **If it says 🟡 SUSPICIOUS:**
  - Be cautious. 
  - Check the website address (URL) at the top of your screen very carefully. Does it look exactly correct?
  - If you are in doubt, do not log in. Instead, open a new tab and navigate to the website manually by typing the address yourself (e.g., type `www.microsoft.com`).
  
- **If you already entered your password on a flagged site:**
  - Change your password immediately using a safe device or a safe browser tab.
  - Contact your IT department or the customer support of the service you were logging into to let them know.

---

## Frequently Asked Questions (FAQ)

**Does this slow down my browsing?**
No, not at all! The extension runs quietly in the background and has a minimal impact on your computer's performance. You won't even notice it's there until it needs to warn you.

**Does this replace my antivirus software?**
No. Think of your antivirus as the security guard for your computer's hard drive, making sure you don't download malicious files. This extension is a specialist security guard specifically for your web browser, focused entirely on stopping login interception attacks. They work great together!

**Does this work on all websites?**
Yes, it monitors all the websites you visit, but it pays special attention to login pages for major services, as those are the most common targets for scammers.

**Can criminals bypass this?**
Like all security tools, it is not 100% perfect. However, it checks many different things simultaneously. While a criminal might be able to fake one or two things, faking all of them perfectly is incredibly difficult. This tool raises the bar significantly.

**Does this send my data anywhere?**
Absolutely not. Your privacy is critical. All the analysis happens locally, right inside your browser. The extension does not send your browsing history, your passwords, or any other data to external servers.

---

## Why this matters

You might be wondering, "Why do I need this if I already use Two-Factor Authentication (2FA)?" 

That's a great question. For a long time, 2FA (like getting a text message with a code) was the ultimate protection. However, the cyber attacks this extension stops—known as Adversary-in-the-Middle (AiTM) attacks—are designed specifically to **bypass traditional two-factor authentication.**

These attacks are currently one of the fastest-growing threats in cybersecurity. Major companies, government institutions, and everyday people have been targeted and compromised by them. 

By installing this tool, you are adding an essential, modern line of defense to your digital life. You are helping to keep your personal information, your company's data, and your identity safe from sophisticated online criminals. 

Thank you for taking your security seriously!
