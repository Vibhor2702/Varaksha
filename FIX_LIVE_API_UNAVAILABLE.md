## FIX: "Live API unavailable" Error

### Quick Fix for Cloudflare Pages

If you see: **"Live API unavailable. Set NEXT_PUBLIC_API_URL in Cloudflare Pages..."**

#### Step 1: Get Your Railway URL
1. Go to https://railway.app
2. Find your Varaksha project
3. Copy the production URL (should look like: `https://varaksha-production.up.railway.app`)

#### Step 2: Set Environment Variable in Cloudflare
1. Go to Cloudflare Pages → Your Project Name
2. Click **Settings** tab
3. Click **Environment Variables**
4. Click **Add Variable**
5. **Variable name**: `NEXT_PUBLIC_API_URL`
6. **Value**: Paste your Railway URL (e.g., `https://varaksha-production.up.railway.app`)
7. Click **Add variable**

#### Step 3: Redeploy Frontend
1. Go to **Deployments** tab
2. Find your latest deployment
3. Click the **3-dot menu** → **Retry deployment**
4. Wait for deployment to complete (usually 1-2 minutes)

#### Step 4: Test
1. Navigate to https://varaksha.pages.dev
2. Go to Module A (Intelligence Sandbox)
3. Click "Test Transaction" button
4. Should now work without the API error

---

### Troubleshooting

**Still seeing the error after redeploy?**
- Clear browser cache (Ctrl+Shift+Delete)
- Hard refresh (Ctrl+Shift+R)
- Wait 30 seconds for CDN cache to clear

**What if you don't have a Railway backend?**
- The Gateway must be running on Railway for this to work
- Check that your Railway deployment is active and not suspended
- Verify the Health endpoint: `curl https://your-url.up.railway.app/health`

**Local Development?**
You don't need NEXT_PUBLIC_API_URL locally. The frontend will auto-detect:
- Run gateway on port 8000: `cd gateway && cargo run --release`
- Run frontend on port 3000: `npm run dev`
- The frontend will communicate with `http://localhost:8000` automatically

---

### What is NEXT_PUBLIC_API_URL?

This environment variable tells the Next.js frontend where to send fraud scoring requests:

```
Frontend (varaksha.pages.dev) 
    ↓ POSTS to NEXT_PUBLIC_API_URL/v1/tx
Gateway (Railway backend)
    ↓
Sidecar (Python ML service)
    ↓
ML Models (ONNX)
```

Without it set, the frontend can't reach your backend to score transactions.
