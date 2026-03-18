# QUICK START: Get Varaksha Working NOW

## ✅ Status: Backend is WORKING

Backend verification just ran - **it's up and responding!**

```
Backend: https://varaksha-production.up.railway.app ✓
Health: {status: ok, version: 2.1.0} ✓  
API: Scoring transactions correctly ✓
```

---

## 🎯 What You Need to Do (3 Steps, 2 Minutes)

### Step 1: Go to Cloudflare Pages
https://dash.cloudflare.com/pages

### Step 2: Set ONE Environment Variable
1. Click your Varaksha project
2. Go to **Settings** → **Environment Variables**
3. Click **Add variable**
4. Fill in:
   - **Name**: `NEXT_PUBLIC_API_URL`
   - **Value**: `https://varaksha-production.up.railway.app`
5. Click **Save**

### Step 3: Redeploy Frontend
1. Go to **Deployments** tab
2. Find your latest deploy (should say "Active")
3. Click the 3 dots → **Retry deployment**
4. Wait 30-60 seconds

---

## ✅ Test It Works
1. Go to https://varaksha.pages.dev
2. Click "Module A — Intelligence Sandbox"
3. Enter test data and click "Test Transaction"
4. Should return ALLOW/FLAG/BLOCK withrisk score

---

## 🔍 If It Still Doesn't Work

Run this test to verify backend is still accessible:
```bash
python verify_backend_connection.py
```

Should show all [OK] checkmarks if backend is working.

---

## 📊 What's Happening Behind the Scenes

```
Your Browser
    ↓ (Click "Test Transaction")
    ↓
Cloudflare Pages (varaksha.pages.dev)
    ├─ Checks: Is NEXT_PUBLIC_API_URL set?
    ├─ YES → Uses https://varaksha-production.up.railway.app
    └─ NO → Shows error (THAT'S WHE YOU ARE NOW)
    ↓
Railway Gateway API /v1/tx
    ├─ Deserializes your transaction
    ├─ Calls Python sidecar service
    └─ Returns verdict + risk score
    ↓
Python Sidecar (FastAPI)
    ├─ Loads ONNX models
    ├─ Random Forest (RF)
    ├─ Isolation Forest (IF)
    └─ Returns risk_score
    ↓
Back to Browser
    └─ Shows ALLOW/FLAG/BLOCK
```

**The backend is ready.** You just need to tell Cloudflare where it is!

---

## 💡 Why This Is Needed

Varaksha is a **static site** on Cloudflare Pages (no backend needed at build time). When you click "Test Transaction", it needs to know where your Railway backend is. That's what `NEXT_PUBLIC_API_URL` does - it's like leaving a note: "When you need to score a transaction, go HERE."

---

## 🚀 Done!

Once you add the env var and redeploy, everything will just work. The backend is already online and scoring transactions. You just need to connect the wires!
