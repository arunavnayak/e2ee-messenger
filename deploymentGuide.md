# Quick Deployment Guide

## Files to Upload to Your Server

### **Required Files** (Replace existing):
1. `main.py` - ⚠️ CRITICAL - Contains WebSocket auth and rate limiting
2. `models.py` - ⚠️ CRITICAL - Contains SessionToken model
3. `app.js` - ⚠️ CRITICAL - Secure client-side logic
4. `crypto.js` - Updated with session token support
5. `requirements.txt` - Updated dependencies

### **New Files** (Add these):
6. `rate_limiter.py` - ⚠️ NEW - Rate limiting system

### **Unchanged Files** (Keep existing):
- `database.py`
- `status.py`
- `index.html`
- `render.yaml`

---

## Deployment Steps for Render.com

### **Option 1: Git Deployment (Recommended)**

```bash
# 1. Navigate to your project directory
cd /path/to/your/e2ee-messenger

# 2. Replace the files
# Copy all the updated files from the outputs directory to your project

# 3. Add the new rate_limiter.py file
# Copy rate_limiter.py to your project root

# 4. Commit changes
git add .
git commit -m "Security improvements: WebSocket auth, rate limiting, no password storage"

# 5. Push to trigger auto-deployment
git push origin master

# 6. Render will automatically deploy
# Watch the deployment logs at dashboard.render.com
```

### **Option 2: Manual File Upload**

If you're not using Git:

1. Go to your Render dashboard
2. Select your web service
3. Go to "Shell" tab
4. Upload each file individually
5. Restart the service

---

## Post-Deployment Verification

### **1. Check Health Endpoint**
```bash
curl https://your-app-name.onrender.com/health
```

Expected response:
```json
{
  "status": "healthy",
  "database": "healthy",
  "timestamp": "2026-02-08T12:34:56.789Z"
}
```

### **2. Check System Status**
```bash
curl https://your-app-name.onrender.com/system-status
```

### **3. Test Login Flow**

1. Open your app in browser
2. Open DevTools → Application → Storage → Session Storage
3. Register a new account
4. Verify `currentPassword` is NOT in sessionStorage ✅
5. Verify you can login
6. Verify WebSocket connects (check Console logs)
7. Send a message to another user
8. Try sending 50 messages rapidly (should get rate limited)

### **4. Test Rate Limiting**

**Login Rate Limit:**
```bash
# Try 6 failed login attempts quickly
# Should get locked out for 5 minutes after 5th attempt
```

**API Rate Limit:**
```bash
# Make 100 rapid requests to /api/users
for i in {1..100}; do curl https://your-app.onrender.com/api/users; done

# Should start returning 429 (Too Many Requests) after ~60 requests
```

---

## Database Migration

The SessionToken table will be created automatically by SQLAlchemy on first run.

**If you need to manually verify:**

```bash
# SSH into Render shell or use database client
psql $DATABASE_URL

# Check if table exists
\dt session_tokens

# Should show:
#  Schema |      Name       | Type  |        Owner        
# --------+-----------------+-------+---------------------
#  public | session_tokens  | table | e2ee_messenger_user
```

---

## Troubleshooting

### **Problem: WebSocket not connecting**

**Solution:**
1. Check browser console for errors
2. Verify session_token is in login response
3. Check server logs for authentication errors

```bash
# In Render dashboard → Logs
# Look for: "WebSocket authenticated successfully"
```

### **Problem: Rate limiting too aggressive**

**Solution:**
Adjust limits in `rate_limiter.py`:

```python
# Less aggressive settings
self.api_limiter = RateLimiter(
    requests_per_minute=120,  # Increased from 60
    burst_size=30             # Increased from 20
)
```

### **Problem: Users can't login**

**Solution:**
1. Check database connectivity in `/health` endpoint
2. Verify PostgreSQL is running
3. Check for failed migration logs
4. Clear browser cache and try again

### **Problem: Database connection errors**

**Check render.yaml:**
```yaml
envVars:
  - key: DATABASE_URL
    fromDatabase:
      name: e2ee-db  # ← Verify this matches your database name
      property: connectionString
```

---

## Important Notes

### **⚠️ Breaking Changes**

1. **All existing users will need to re-login** after deployment
2. Existing WebSocket connections will be terminated
3. Password change now requires current password entry

### **📊 Performance Impact**

- Minimal latency increase (~5-10ms per request)
- Database: +2 queries per login (token creation + cleanup)
- Memory: ~1MB per 10,000 rate limit buckets

### **🔐 Security Improvements**

- ✅ Password no longer in browser storage
- ✅ WebSocket connections authenticated
- ✅ Brute-force protection (5 attempts → 5 min lockout)
- ✅ API rate limiting (60 requests/min)
- ✅ Message flooding prevention (30 messages/min)

---

## Rollback Plan

If something goes wrong:

```bash
# Revert to previous commit
git log --oneline  # Find previous commit hash
git revert <commit-hash>
git push origin master
```

Or restore previous files manually.

---

## Monitoring After Deployment

### **First 24 Hours:**

Monitor these metrics:
- [ ] Login success rate
- [ ] WebSocket connection rate
- [ ] Rate limit hit frequency
- [ ] Database query performance
- [ ] Error logs

### **Week 1:**

- [ ] Session token cleanup working
- [ ] No memory leaks in rate limiters
- [ ] User complaints about rate limiting
- [ ] Database size increase (session_tokens table)

---

## File Structure Reference

```
your-project/
├── main.py              ← UPDATED (WebSocket auth, rate limiting)
├── models.py            ← UPDATED (SessionToken model)
├── rate_limiter.py      ← NEW (Rate limiting system)
├── app.js               ← UPDATED (No password storage, WS auth)
├── crypto.js            ← UPDATED (Session token functions)
├── requirements.txt     ← UPDATED (Dependencies)
├── database.py          (unchanged)
├── status.py            (unchanged)
├── index.html           (unchanged)
└── render.yaml          (unchanged)
```

---

## Success Criteria

Deployment is successful when:

- ✅ Health endpoint returns healthy database status
- ✅ Users can register and login
- ✅ WebSocket connects with authentication
- ✅ Messages send/receive correctly
- ✅ Rate limiting triggers appropriately
- ✅ No password in browser sessionStorage
- ✅ Session tokens expire after 24 hours
- ✅ Failed login attempts trigger lockout

---

## Support

If you encounter issues:

1. **Check Render Logs:**
    - Dashboard → Your Service → Logs
    - Look for Python errors or WebSocket issues

2. **Check Browser Console:**
    - F12 → Console
    - Look for JavaScript errors or WebSocket connection issues

3. **Test Individual Components:**
    - Test `/health` endpoint
    - Test `/api/login` with valid credentials
    - Test WebSocket connection manually

4. **Database Issues:**
    - Verify DATABASE_URL environment variable
    - Check PostgreSQL is running
    - Verify session_tokens table exists

---

## Next Steps After Deployment

Once everything is working:

1. **Monitor for 48 hours** - Check logs and metrics
2. **Gather user feedback** - Any issues with rate limiting?
3. **Tune rate limits** - Adjust if needed based on usage
4. **Plan next improvements** - Forward secrecy, 2FA, etc.

Good luck with your deployment! 🚀