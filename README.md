# 🔐 Login Activity Checker

A Streamlit app that helps you see where and when your accounts were signed in.

> **Important:** no app can look up where an email address is logged in. This
> tool works from the **security-alert emails your services already sent you**
> ("New sign-in", "Security alert", ...). Use it only with your **own** emails.

## What it does

1. You upload `.eml` / `.txt` files (or paste text) of alert emails.
2. Links and long numbers (such as one-time codes) are removed locally.
3. A Groq AI model extracts a table: service, event, device, location, time.
4. It flags anything suspicious, for example a sender domain that doesn't match
   the service, and explains why.

Nothing is stored by the app. The cleaned email text is sent to the Groq API
for analysis.

## How to get the emails

- Search your mailbox for `new sign-in`, `security alert` or `new login`.
- In Gmail: open the email, click ⋮, then **Download message** to get an `.eml`
  file. Or simply copy and paste the text.

## Run locally

```bash
pip install -r requirements.txt
```

Create `.streamlit/secrets.toml` (never commit this file):

```toml
GROQ_API_KEY = "your_groq_api_key_here"
```

```bash
streamlit run app.py
```

Get a free key at <https://console.groq.com/keys>.

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub.
2. Go to <https://share.streamlit.io> and click **Create app**.
3. Choose your repo, branch `main`, main file `app.py`.
4. Under **Advanced settings → Secrets**, paste:
   ```toml
   GROQ_API_KEY = "your_groq_api_key_here"
   ```
5. Click **Deploy**.

## Changing the AI model

The default is `openai/gpt-oss-120b`. If Groq retires it, add this to your
secrets instead of editing code:

```toml
GROQ_MODEL = "model-name-from-console.groq.com/docs/models"
```

## Limits

- Up to 15 emails per run, 2 MB per file.
- The AI can make mistakes. For the real list of active sessions, check each
  service's own security or devices page.

## Files

- `app.py` – the Streamlit app
- `requirements.txt` – dependencies
- `README.md` – this file
