// Minimal worker that logs in to webDiplomacy phpBB and fetches a page title.
// Public routes: GET /, GET /healthz
// Protected route: POST /preview   (Authorization: Bearer WORKER_TOKEN)

import express from 'express'

const app = express()
app.use(express.json())

const PORT = process.env.PORT || 8080
const USER = process.env.FORUM_USERNAME || ''
const PASS = process.env.FORUM_PASSWORD || ''
const TOKEN = process.env.WORKER_TOKEN || '' // set this in Render + Vercel

// --- tiny helpers -----------------------------------------------------------

function splitSetCookie(sc) {
  return sc.split(/,\s*(?=[^;,\s]+=)/g)
}
function mergeCookiePairs(...pairs) {
  const jar = {}
  for (const p of pairs) {
    if (!p) continue
    const keyVal = p.split(';', 1)[0]
    const eq = keyVal.indexOf('=')
    if (eq > 0) {
      const name = keyVal.slice(0, eq).trim()
      const val = keyVal.slice(eq + 1).trim()
      if (name && val) jar[name] = val
    }
  }
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ')
}
async function fetchWithJar(url, init = {}, cookieHeader) {
  const headers = new Headers(init.headers || {})
  if (cookieHeader) headers.set('cookie', cookieHeader)
  const res = await fetch(url, { ...init, headers })
  const setCookie = res.headers.get('set-cookie') || ''
  const pairs = setCookie ? splitSetCookie(setCookie) : []
  return { res, pairs }
}
function extractHiddenInputs(html) {
  const out = {}
  const re = /<input[^>]+type=["']hidden["'][^>]*>/gi
  const nameRe = /name=["']([^"']+)["']/i
  const valRe = /value=["']([^"']*)["']/i
  let m
  while ((m = re.exec(html))) {
    const tag = m[0]
    const name = tag.match(nameRe)?.[1]
    const val = tag.match(valRe)?.[1] ?? ''
    if (name) out[name] = val
  }
  return out
}
function extractTitle(html) {
  const titleTag = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]
  const og = html.match(/<meta[^>]+property=["']og:title["'][^>]*content=["']([^"']+)["']/i)?.[1]
  const tw = html.match(/<meta[^>]+name=["']twitter:title["'][^>]*content=["']([^"']+)["']/i)?.[1]
  const t = (titleTag || og || tw || '').replace(/\s+/g, ' ').trim()
  return t || null
}
function isPhpBB(url) {
  return /https?:\/\/(www\.)?webdiplomacy\.net\/contrib\/phpBB3\//i.test(url)
}

/** Try to infer login success from cookies: phpBB sets ..._u cookie; "1" means guest */
function phpbbUserCookieSaysLoggedIn(cookieHeader) {
  if (!cookieHeader) return false
  const parts = cookieHeader.split(';').map(s => s.trim())
  // look for phpbb3_<hash>_u
  const u = parts.find(p => /phpbb3_[^=]+_u=/.test(p))
  if (!u) return false
  const val = u.split('=')[1]
  return val && val !== '1'
}

// --- public routes ----------------------------------------------------------

app.get('/', (_req, res) => res.status(200).send('webdip-mafia-worker: ok'))
app.get('/healthz', (_req, res) => res.json({ ok: true }))

// --- auth middleware (used only on protected routes) -----------------------

function auth(req, res, next) {
  if (!TOKEN) return res.status(500).json({ error: 'WORKER_TOKEN not set' })
  const hdr = req.get('authorization') || ''
  if (!hdr.startsWith('Bearer ') || hdr.slice(7) !== TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  next()
}

// --- protected routes -------------------------------------------------------

app.post('/preview', auth, async (req, res) => {
  try {
    const url = String(req.body?.url || '').trim()
    if (!/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'Valid URL required' })

    // Use a very realistic desktop Chrome UA (no "bot"/"worker" tokens)
    const commonHeaders = {
      'user-agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        + 'Chrome/124.0.0.0 Safari/537.36',
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'accept-language': 'en-US,en;q=0.9',
      'upgrade-insecure-requests': '1',
      // sec- headers aren’t strictly required by phpBB, but they don’t hurt:
      'sec-fetch-site': 'same-origin',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-dest': 'document',
    }

    // Non-phpBB: unauthenticated fetch
    if (!isPhpBB(url)) {
      const r = await fetch(url, { headers: commonHeaders })
      const ct = r.headers.get('content-type') || ''
      const html = await r.text()
      if (!/html/i.test(ct)) return res.json({ url, title: null, note: `Unsupported content-type: ${ct}`, status: r.status })
      return res.json({ url, title: extractTitle(html), status: r.status })
    }

    if (!USER || !PASS) return res.status(500).json({ error: 'Missing FORUM_USERNAME/FORUM_PASSWORD' })

    const BASE = 'https://www.webdiplomacy.net/contrib/phpBB3/'
    const LOGIN = BASE + 'ucp.php?mode=login'

    // 1) GET login page
    let cookieJar = ''
    const { res: r1, pairs: p1 } = await fetchWithJar(
      LOGIN,
      { method: 'GET', headers: { ...commonHeaders, referer: BASE } }
    )
    cookieJar = mergeCookiePairs(...p1)
    const loginHtml = await r1.text()
    const hidden = extractHiddenInputs(loginHtml)

    // 2) POST login; ask phpBB to redirect us to the target topic after login
    const redirectPath = url.startsWith(BASE) ? '.' + url.slice(BASE.length - 1) : './index.php'
    const form = new URLSearchParams({
      username: USER,
      password: PASS,
      login: 'Login',
      redirect: redirectPath,
      autologin: 'on',
      ...hidden
    })
    const { res: r2, pairs: p2 } = await fetchWithJar(
      LOGIN,
      {
        method: 'POST',
        headers: { ...commonHeaders, 'content-type': 'application/x-www-form-urlencoded', referer: LOGIN },
        redirect: 'follow',
        body: form.toString()
      },
      cookieJar
    )
    cookieJar = mergeCookiePairs(cookieJar, ...p2)

    // 3) Verify login
    //    A) cookie says logged-in user (phpbb3_*_u != 1)
    //    B) page shows Logout link or username
    let loginOk = phpbbUserCookieSaysLoggedIn(cookieJar)
    if (!loginOk) {
      const { res: checkRes } = await fetchWithJar(
        BASE + 'index.php',
        { method: 'GET', headers: { ...commonHeaders, referer: LOGIN } },
        cookieJar
      )
      const checkHtml = await checkRes.text()
      loginOk = /ucp\.php\?mode=logout/i.test(checkHtml) || (USER && checkHtml.includes(USER))
    }

    // 4) Fetch the target
    const { res: topicRes } = await fetchWithJar(
      url,
      { method: 'GET', headers: { ...commonHeaders, referer: BASE } },
      cookieJar
    )
    const status = topicRes.status
    const ctype = topicRes.headers.get('content-type') || ''
    const html = await topicRes.text()

    if (!/html/i.test(ctype)) {
      return res.json({ url, title: null, note: `Unsupported content-type: ${ctype}`, status, loginOk })
    }
    if (/only users can view/i.test(html) || /you must be registered and logged in/i.test(html)) {
      return res.json({ url, title: null, note: 'Page restricted after login (anti-bot)', status, loginOk })
    }

    return res.json({ url, title: extractTitle(html), status, loginOk })
  } catch (e) {
    return res.status(500).json({ error: 'Preview failed' })
  }
})

// --- start ------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`worker listening on :${PORT}`)
})
