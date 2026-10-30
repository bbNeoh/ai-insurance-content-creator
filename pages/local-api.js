// ════════════════════════════════════════════════════════════════════
// Phone / GitHub Pages version — no server.
// Answers the page's /api/* calls right here in the browser, sending AI
// requests straight to OpenAI with the key saved on this device only.
// Prompts mirror server.js — keep them in sync when you change one.
// ════════════════════════════════════════════════════════════════════
(function () {
  const KEY_STORE = 'openai_api_key';
  const MODEL     = 'gpt-4o-mini';
  const LANG_NAMES = {
    en: 'English',
    zh: 'Simplified Chinese (简体中文)',
    my: 'Bahasa Malaysia (Malay)',
    ta: 'Tamil (தமிழ்)',
  };

  const getKey = () => { try { return localStorage.getItem(KEY_STORE) || ''; } catch { return ''; } };
  const setKey = k => { try { localStorage.setItem(KEY_STORE, k); } catch {} };
  const clearKey = () => { try { localStorage.removeItem(KEY_STORE); } catch {} };

  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  // ── Streaming: OpenAI SSE → the app's own {type:'text'|'done'|'error'} SSE ──
  function streamResponse(system, prompt) {
    const enc = new TextEncoder();
    const body = new ReadableStream({
      async start(controller) {
        const send = obj => controller.enqueue(enc.encode(`data: ${JSON.stringify(obj)}\n\n`));
        try {
          const key = getKey();
          if (!key) { showKeyScreen(); throw new Error('Please enter your OpenAI key first.'); }
          const r = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
            body: JSON.stringify({
              model: MODEL, max_tokens: 4096, stream: true,
              messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
            }),
          });
          if (!r.ok) throw new Error(await openaiError(r));
          const reader = r.body.getReader(), dec = new TextDecoder();
          let buf = '';
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += dec.decode(value, { stream: true });
            const lines = buf.split('\n'); buf = lines.pop() ?? '';
            for (const line of lines) {
              if (!line.startsWith('data: ')) continue;
              const raw = line.slice(6).trim();
              if (!raw || raw === '[DONE]') continue;
              try {
                const text = JSON.parse(raw).choices?.[0]?.delta?.content || '';
                if (text) send({ type: 'text', text });
              } catch {}
            }
          }
          send({ type: 'done' });
        } catch (err) {
          send({ type: 'error', message: err.message });
        }
        controller.close();
      },
    });
    return new Response(body, { headers: { 'Content-Type': 'text/event-stream' } });
  }

  async function openaiError(r) {
    let msg = `OpenAI error ${r.status}`;
    try { msg = (await r.json()).error?.message || msg; } catch {}
    if (r.status === 401) { clearKey(); showKeyScreen('That key was rejected by OpenAI. Please check it and try again.'); }
    if (r.status === 429) msg += ' — check your OpenAI credit / billing.';
    return msg;
  }

  // ── Handlers (same prompts as server.js) ──────────────────────────
  const routes = {
    'GET /api/config':          () => json({ allowRegistration: false, authEnabled: false, gateEnabled: false, unlocked: true }),
    'GET /auth/me':             () => json({ authEnabled: false }),
    'POST /auth/logout':        () => json({ ok: true }),
    'GET /api/social-status':   () => json({ facebook: false, instagram: false, linkedin: false }),
    'GET /api/image-providers': () => json({ dalle: !!getKey(), seedream: false, gemini: false, heygen: false }),

    'POST /api/scrape-profile': async ({ url }) => {
      if (!url) return json({ error: 'URL required' }, 400);
      try {
        const r = await fetch(`https://r.jina.ai/${url}`, { headers: { Accept: 'text/plain', 'X-Return-Format': 'text' } });
        if (!r.ok) return json({ error: `Could not fetch page (${r.status}). It may require login.` }, 400);
        const raw = await r.text();
        if (/sign.?in|log.?in|join now|create account|authwall/i.test(raw.slice(0, 1000)))
          return json({ error: 'This page requires login. Please paste your posts manually.' }, 403);
        const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 40)
          .filter(l => !/^https?:\/\//i.test(l)).slice(0, 120);
        return json({ content: lines.join('\n\n'), lineCount: lines.length });
      } catch (err) {
        return json({ error: 'Could not read that page — paste posts manually.' }, 500);
      }
    },

    'POST /api/analyze-style': ({ facebookPosts, linkedinPosts, name }) => {
      const allPosts = [];
      if (facebookPosts?.trim()) allPosts.push(`=== FACEBOOK POSTS ===\n${facebookPosts.trim()}`);
      if (linkedinPosts?.trim()) allPosts.push(`=== LINKEDIN POSTS ===\n${linkedinPosts.trim()}`);
      if (!allPosts.length) return json({ error: 'No posts provided' }, 400);
      return streamResponse(
        `You are an elite ghostwriter and writing style analyst. Your job is to study someone's actual social media posts and extract every detail of their unique voice — so precisely that future AI-generated content is indistinguishable from their real writing. Be specific with real examples from the posts, not generic descriptions.`,
        `Study every single post below written by ${name || 'this insurance advisor'} and produce a detailed Writing Style DNA profile. Pull REAL examples and quotes from the posts to illustrate each point.

${allPosts.join('\n\n')}

---
Return in this exact markdown format, filling every field with SPECIFIC observations and ACTUAL examples from the posts above:

## 🧬 Writing Style DNA — ${name || 'Agent Profile'}

### 🎙️ Tone & Voice
- **Overall Tone:** (e.g. warm and conversational / authoritative / motivational)
- **Energy Level:** (e.g. calm and reassuring / high-energy / thoughtful)
- **Personality:** (e.g. relatable friend / trusted expert / storyteller)
- **Real example of tone:** (quote a line that best shows their voice)

### 📐 Sentence & Structure
- **Sentence Length:** (e.g. short punchy sentences under 10 words / medium / mix)
- **Paragraph Style:** (e.g. 1-sentence paragraphs / 2–3 lines / long blocks)
- **Line breaks:** (e.g. uses lots of white space / dense paragraphs)
- **Formatting Habits:** (e.g. uses bold, lists, numbers, dashes)

### 😊 Emoji Usage
- **Frequency:** (Heavy 5+/post / Moderate 2–4 / Minimal 0–1)
- **Placement:** (e.g. start of line, mid-sentence, end of post)
- **Commonly used emojis:** (list the actual emojis they use most)

### #️⃣ Hashtag Style
- **Count per post:** (e.g. 3–5 / 6–10 / none)
- **Placement:** (end of post / inline within text)
- **Language of hashtags:** (English / Malay / mix)
- **Common hashtag themes:** (list examples)

### 🪝 Hook Patterns (how posts OPEN)
- **Primary hook style:** (question / bold statement / personal story / surprising fact)
- **Signature openers:** (list 2–3 real opening lines from their posts)

### 📣 CTA & Closing Style
- **CTA type:** (soft question / direct call / reflection prompt / no CTA)
- **Signature closing phrases:** (quote actual endings from their posts)

### 📖 Vocabulary & Language
- **Language mix:** (e.g. pure English / pure Malay / Manglish / mix)
- **Formality:** (casual slang / semi-formal / professional)
- **Recurring words/phrases they love:** (list real examples)
- **Words/phrases they NEVER use:** (based on observation)

### 📏 Post Length & Format
- **Typical length:** (short <80w / medium 80–200w / long 200w+)
- **Format preference:** (flowing prose / bullet lists / numbered points / hybrid)

### ✨ Signature Style Markers
- **What makes their writing instantly recognisable:**
- **Recurring themes or values:**
- **Their unique storytelling approach:**

### 🎯 AI Replication Instructions
When writing content in this person's style:
- DO: (list 5 specific things to always do)
- AVOID: (list 5 specific things to never do)
- Sample opening line in their style:
- Sample closing line in their style:

---
*Style DNA captured from ${allPosts.length > 1 ? 'Facebook + LinkedIn' : 'social media'} posts by ${name || 'this agent'}.*`
      );
    },

    'POST /api/calendar': (b) => {
      const name         = (b.agentName || '').trim() || 'an insurance advisor';
      const lang         = LANG_NAMES[b.language] || 'English';
      const styleProfile = (b.styleProfile || '').trim();
      const langNote     = `CRITICAL REQUIREMENT: You MUST write ALL content — including every table header, content theme, hook, key message, CTA, and any other text — ENTIRELY in ${lang}. Do not use any other language.`;
      const styleNote    = styleProfile
        ? `\n\nWRITING STYLE: Use the following Style DNA profile to shape the tone, hooks, and CTAs in the calendar:\n${styleProfile}`
        : '';
      return streamResponse(
        `You are an expert insurance content strategist and social media manager. You always use proper markdown table formatting. ${langNote}`,
        `${langNote}

Create a 7-day social media content calendar for ${name}.

Format as a clean markdown table with EXACTLY these columns (translate the column headers to ${lang}):
| Day | Content Theme | Post Topic / Hook | Key Message | Post Format | CTA |

Content Theme options (write in ${lang}): Education, Myth-Busting, Emotional Storytelling, Tips

Topics must cover a mix of:
• Financial security for children
• Medical protection
• Future planning (retirement, education fund)
• Common insurance misconceptions
• Real-life emotional angles (family, protection, peace of mind)

Post Format: each row must say either "Static Post" or "Reel" (write in ${lang})
Audience: Young Parents/Families AND Working Professionals planning for financial security
Tone: Warm, professional, reassuring — NO hard selling
${styleNote}

Generate the complete 7-day calendar table now. ${langNote}`
      );
    },

    'POST /api/post': ({ calendarContent, dayNumber, agentName, language, styleProfile }) => {
      const name      = (agentName || '').trim() || 'an insurance advisor';
      const lang      = LANG_NAMES[language] || 'English';
      const langNote  = `CRITICAL REQUIREMENT: Write the ENTIRE post — every word, sentence, emoji caption, and hashtag description — in ${lang} only.`;
      const styleNote = (styleProfile || '').trim()
        ? `\n\n════ STYLE DNA — HIGHEST PRIORITY ════
You are ghostwriting for ${name}. You MUST write this post so it sounds EXACTLY like them — not like a generic AI post.
Follow the "AI Replication Instructions" in the Style DNA below. Use their actual vocabulary, sentence rhythm, emoji patterns, hook style, and closing phrases.
A reader who knows ${name} personally should not be able to tell the difference.

${styleProfile}
════════════════════════════════════`
        : '';
      return streamResponse(
        `You are an expert social media copywriter specializing in insurance and financial advisory content. ${langNote}`,
        `${langNote}

Using the 7-day content calendar below, write a complete ready-to-publish social media post for Day ${dayNumber}.

CALENDAR:
${calendarContent}

Structure the post using these 3 sections IN ORDER, but DO NOT include any section headers or labels (no "HOOK", "VALUE", "CALL-TO-ACTION", or any translated equivalents) — write it as one seamless flowing post:

1. HOOK (do not print this label): A surprising or thought-provoking opening that stops the scroll. 1–2 sentences max.

2. VALUE (do not print this label): An educational insight, myth-busting explanation, or emotional story tied to Day ${dayNumber}'s topic. 3–5 short paragraphs.

3. CALL-TO-ACTION (do not print this label): A soft CTA — a reflective question, invite to comment, or prompt to save/share.

End with one engaging question on its own line to spark comments.
Add relevant emoji throughout. Add 6–8 hashtags at the end.
IMPORTANT: Output only the post content — no section headers, no labels, no structural markers.

Written for: ${name}
Tone: Professional, empathetic — NOT salesy
Audience: Young parents and working adults who care about family protection
${styleNote}
${langNote}`
      );
    },

    'POST /api/image-prompt': ({ postCaption }) => streamResponse(
      'You are an expert AI image prompt engineer specializing in lifestyle, family, and professional photography for social media in Southeast Asia.',
      `Based on the insurance post caption below, generate ONE detailed image generation prompt in English.

POST CAPTION:
${postCaption}

The prompt must include:
• People: Southeast Asian appearance — warm medium skin tones, dark hair, East/Southeast Asian facial features; authentic, natural-looking faces
• Setting: Malaysian or Southeast Asian environment — modern Malaysian home, city café, suburban neighbourhood, hospital, office, or outdoor park in a tropical setting
• Clothing: appropriate Malaysian everyday attire — e.g. modest traditional or smart casual wear, business attire; culturally appropriate
• Emotional mood: warm, calm, hopeful, confident, reassuring
• Visual style: photorealistic lifestyle photography OR soft cinematic
• Color palette: warm soft tones, gentle blues, natural light — nothing cold or clinical
• Composition: framing, depth of field, subject placement
• Platform: optimized for Instagram/Facebook square or portrait (1:1 or 4:5 ratio)

Requirements:
✓ Human-centric — real-looking Southeast Asian people, genuine emotions
✓ Family-friendly and brand-safe
✓ Culturally authentic — looks like it was shot in Malaysia
✗ DO NOT mention any specific ethnicity, race, or nationality of people
✗ NO Western or non-Asian faces
✗ NO fear-based, dark, dramatic, or negative imagery
✗ NO text overlays in the image

Output ONLY the image prompt text in English — no title, no explanation.
Ready to paste into Midjourney, DALL·E 3, Gemini Imagen, or Dreamina.`
    ),

    'POST /api/video-script': ({ postCaption, agentName }) => {
      const name = (agentName || '').trim() || 'an insurance advisor';
      return streamResponse(
        'You are an expert short-form video script writer for insurance agents and financial advisors in Malaysia. Write all scripts in English.',
        `Based on the post caption below, write a first-person talking-head video script in English for Instagram Reels / TikTok / YouTube Shorts.

IMPORTANT — Asian context: The speaker is a Malaysian insurance advisor (${name}). The audience is everyday Malaysians — families, young working adults, couples. Use relatable Malaysian life references (e.g. school fees, ageing parents, kampung, EPF, hospital bills) where natural. Keep language simple and warm.

POST CAPTION:
${postCaption}

Format with these clearly labelled sections:

⏱️ OPENING HOOK — 0 to 3 seconds
[ON-SCREEN TEXT: what appears on screen]
SPOKEN: the actual words spoken aloud here

📹 CORE MESSAGE — 4 to 50 seconds
SPOKEN: first spoken sentence
[B-ROLL: optional visual cue]
SPOKEN: next spoken sentence [PAUSE]
SPOKEN: continue spoken content

🎯 CLOSE + SOFT CTA — last 5 to 10 seconds
SPOKEN: closing words and soft call to action

Rules:
• EVERY line of spoken dialogue must start with SPOKEN:
• Stage directions go inside [square brackets] on their own line
• First person ("I", "you") throughout
• Speaker: ${name}
• 30–60 seconds when spoken aloud
• Tone: warm, confident, empathetic advisor
• Write entirely in English`
      );
    },

    'POST /api/dreamina-script': ({ postCaption }) => streamResponse(
      'You are an expert cinematic video scriptwriter specialising in short-form AI-generated drama videos for Malaysian social media. Write all scripts in English.',
      `Based on the insurance post caption below, write a cinematic drama video script for AI video generation using Dreamina / CapCut AI.

POST CAPTION:
${postCaption}

═══════════════════════════════════════
STEP 1 — DEFINE CHARACTERS & SETTING
═══════════════════════════════════════
Before writing scenes, define the following and keep them IDENTICAL in every scene:

CHARACTER PROFILES:
• List 1–3 characters. For each:
  - Malaysian name, age, ethnicity (Malay / Chinese / Indian — choose ONE that fits the story)
  - Physical: dark black hair, Southeast Asian skin tone, facial features; specific build
  - Attire: exact Malaysian clothing with colours and accessories — e.g. baju kurung, batik shirt, casual t-shirt with jeans, office wear (must not change between scenes)
  - No Western or non-Asian appearance

ENVIRONMENT:
• Distinctly Malaysian/Southeast Asian location — e.g. modern Malaysian terraced house interior, Malaysian city café with local signage, government hospital corridor, suburban pasar malam, office in KL
• Time of day and lighting (e.g. late afternoon, warm golden tropical light through windows)
• Key Malaysian props / recurring visual elements (e.g. framed family photo, songkok on shelf, thermos of teh tarik, Malaysian ringgit notes, school report card)

═══════════════════════════════════════
STEP 2 — WRITE 3–5 SCENES
═══════════════════════════════════════
Each scene must follow this exact structure:

SCENE [N] — [SCENE TITLE] ([duration, e.g. 0–4s])
[VISUAL: what the camera sees — reference characters by name, use their defined attire and setting]
[CAMERA: movement, e.g. slow zoom in, wide shot, close-up on hands]
[MOOD: atmosphere and colour grade, e.g. warm amber tones, soft bokeh background]
[ACTION: exactly what each character is doing, with specific body language]
[DIALOGUE: "one short spoken line if needed — emotionally resonant"]
[TEXT ON SCREEN: overlay text if needed]

Consistency rules:
• Characters wear EXACTLY the same clothes in every scene — never change attire
• Same location and lighting style throughout unless a scene explicitly transitions
• Reference characters by name in every scene, not as "the man" or "she"
• Props introduced in Scene 1 must reappear where relevant in later scenes
• All characters must look authentically Malaysian/Southeast Asian in every scene description
• Total video: 30–60 seconds
• Tone: emotional, warm, cinematic — everyday Malaysian family story
• End with a moment of relief or hope that ties back to insurance/financial protection
• Write entirely in English`
    ),

    'POST /api/translate': ({ content, language }) => {
      const lang = LANG_NAMES[language] || 'English';
      return streamResponse(
        'You are a professional translator specializing in insurance and financial content for social media. You translate accurately while preserving all formatting.',
        `Translate the following content to ${lang}.

STRICT RULES — follow exactly:
1. Preserve ALL markdown formatting: table pipes |, separator rows ---, bold **, headers #, bullet points -, etc.
2. If content is a markdown table, keep the EXACT same table structure with same number of rows and columns
3. Translate ALL text to ${lang} including table headers, cell content, post body, hooks, and CTAs
4. Keep all emoji exactly as-is
5. For hashtags: translate or adapt them to natural ${lang} equivalents
6. Do NOT add any introduction, explanation, or preamble
7. Output ONLY the translated content — nothing else

CONTENT TO TRANSLATE:
${content}`
      );
    },

    'POST /api/generate-image': async ({ imagePrompt, referenceImages }) => {
      const key = getKey();
      if (!key) { showKeyScreen(); return json({ error: 'Please enter your OpenAI key first.' }, 400); }
      const prompt = enhanceImagePrompt(imagePrompt || '');
      const refs = Array.isArray(referenceImages) ? referenceImages : [];
      try {
        let r;
        if (refs.length) {
          const form = new FormData();
          form.append('model', 'gpt-image-2');
          form.append('prompt', prompt);
          form.append('n', '1');
          form.append('size', '1024x1024');
          refs.forEach((img, i) => {
            const bytes = Uint8Array.from(atob(img.data), c => c.charCodeAt(0));
            form.append(refs.length === 1 ? 'image' : 'image[]', new Blob([bytes], { type: img.mimeType || 'image/png' }), `ref${i}.png`);
          });
          r = await fetch('https://api.openai.com/v1/images/edits', { method: 'POST', headers: { Authorization: `Bearer ${key}` }, body: form });
        } else {
          r = await fetch('https://api.openai.com/v1/images/generations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
            body: JSON.stringify({ model: 'gpt-image-2', prompt, n: 1, size: '1024x1024', quality: 'high' }),
          });
        }
        if (!r.ok) return json({ error: `GPT Image 2 error: ${await openaiError(r)}` }, 500);
        const data = await r.json();
        return json({ imageData: data.data[0].b64_json, mimeType: 'image/png', source: 'gpt-image-2' });
      } catch (err) {
        return json({ error: `GPT Image 2 error: ${err.message}` }, 500);
      }
    },
  };

  function enhanceImagePrompt(prompt) {
    const humanKeywords = [
      'person', 'people', 'man', 'woman', 'men', 'women', 'family', 'couple',
      'agent', 'customer', 'client', 'advisor', 'professional', 'businessman',
      'businesswoman', 'employee', 'staff', 'team', 'group', 'individual',
      'father', 'mother', 'parent', 'child', 'senior', 'elderly', 'adult',
      'he ', 'she ', 'his ', 'her ', 'him ', 'they ', 'their ',
      'face', 'portrait', 'smile', 'smiling', 'sitting', 'standing',
      'orang', 'lelaki', 'perempuan', 'wanita', 'pria',
    ];
    const lower = prompt.toLowerCase();
    if (!humanKeywords.some(kw => lower.includes(kw))) return prompt;
    return prompt + ', East Asian and Southeast Asian appearance, modern urban Malaysian setting, photorealistic';
  }

  // ── Intercept the page's own /api and /auth calls ─────────────────
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    const path = url.startsWith('/') ? url : (() => {
      try { const u = new URL(url); return u.origin === location.origin ? u.pathname : null; } catch { return null; }
    })();
    if (!path || !/^\/(api|auth|admin)\//.test(path)) return realFetch(input, init);

    const method = (init.method || 'GET').toUpperCase();
    const handler = routes[`${method} ${path.split('?')[0]}`];
    if (!handler) {
      return json({ error: 'This feature needs the full (server) version — it is not available in the phone app.' }, 400);
    }
    let body = {};
    try { body = init.body ? JSON.parse(init.body) : {}; } catch {}
    return handler(body);
  };

  // ── OpenAI key screen ─────────────────────────────────────────────
  function showKeyScreen(message) {
    const el = document.getElementById('keyOverlay');
    if (!el) return;
    document.getElementById('keyErr').textContent = message || '';
    document.getElementById('keyErr').style.display = message ? 'block' : 'none';
    el.style.display = 'flex';
    setTimeout(() => document.getElementById('keyInput').focus(), 50);
  }
  window.showKeyScreen = showKeyScreen;

  document.addEventListener('DOMContentLoaded', () => {
    document.body.insertAdjacentHTML('beforeend', `
<div id="keyOverlay" style="display:none;position:fixed;inset:0;z-index:10000;background:linear-gradient(135deg,#1e3a5f,#2563eb);align-items:center;justify-content:center;padding:16px;overflow:auto">
  <form id="keyForm" style="background:#fff;border-radius:16px;padding:28px 22px;width:100%;max-width:380px;box-shadow:0 20px 50px rgba(0,0,0,.25);text-align:center">
    <img src="icons/icon-192.png" alt="" width="64" height="64" style="border-radius:14px;margin-bottom:12px" />
    <h2 style="font-size:1.15rem;color:#0f172a;margin-bottom:6px">Connect your OpenAI key</h2>
    <p style="color:#64748b;font-size:.88rem;line-height:1.5;margin-bottom:16px">
      The app uses your own OpenAI account. Your key is saved <b>only on this device</b> and sent only to OpenAI.
      Get one at <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener">platform.openai.com/api-keys</a>.
    </p>
    <input id="keyInput" type="password" autocomplete="off" placeholder="sk-..." required
      style="width:100%;padding:12px 14px;border:1px solid #cbd5e1;border-radius:10px;font-size:1rem;margin-bottom:12px" />
    <p id="keyErr" style="display:none;color:#ef4444;font-size:.85rem;margin-bottom:10px"></p>
    <button id="keyBtn" type="submit" style="width:100%;padding:12px;border:0;border-radius:10px;background:#f97316;color:#fff;font-weight:700;font-size:1rem;cursor:pointer">Save &amp; start</button>
  </form>
</div>
<button id="keySettingsBtn" type="button" title="Change OpenAI key"
  style="position:fixed;top:10px;right:10px;z-index:900;border:0;border-radius:999px;padding:6px 10px;background:rgba(255,255,255,.9);box-shadow:0 2px 8px rgba(0,0,0,.15);font-size:.8rem;cursor:pointer">🔑 Key</button>`);

    document.getElementById('keySettingsBtn').addEventListener('click', () => showKeyScreen());
    document.getElementById('keyForm').addEventListener('submit', async e => {
      e.preventDefault();
      const btn = document.getElementById('keyBtn'), err = document.getElementById('keyErr');
      const k = document.getElementById('keyInput').value.trim();
      btn.disabled = true; btn.textContent = 'Checking…'; err.style.display = 'none';
      try {
        // Free check: listing models costs nothing.
        const r = await realFetch('https://api.openai.com/v1/models', { headers: { Authorization: `Bearer ${k}` } });
        if (!r.ok) throw new Error(r.status === 401 ? 'OpenAI did not accept this key.' : `OpenAI error ${r.status}`);
        setKey(k);
        location.reload();
      } catch (ex) {
        err.textContent = ex.message === 'Failed to fetch' ? 'No internet connection — please try again.' : ex.message;
        err.style.display = 'block';
        btn.disabled = false; btn.textContent = 'Save & start';
      }
    });

    if (!getKey()) showKeyScreen();
  });
})();
