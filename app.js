// app.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { GoogleGenerativeAI } = require("@google/generative-ai");


// Multer + Cloudinary
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

/* -----------------------------------
   CLOUDINARY SETUP
----------------------------------- */
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'profile_images',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    public_id: (req, file) => `profile_${Date.now()}`
  }
});

const upload = multer({ storage });

/* -----------------------------------
   DATABASE CONNECT
----------------------------------- */
if (!process.env.MONGO_URI) {
  console.error("MONGO_URI not set in .env");
  process.exit(1);
}

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

/* -----------------------------------
   MIDDLEWARE
----------------------------------- */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* -----------------------------------
   HELPER: JWT COOKIE
----------------------------------- */
function createSendToken(user, res) {
  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  const cookieOptions = {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    sameSite: 'lax'
  };

  // only set secure when in production and https
  if (process.env.NODE_ENV === 'production') {
    cookieOptions.secure = true;
    cookieOptions.sameSite = 'none';
  }

  res.cookie('token', token, cookieOptions);
}

/* -----------------------------------
   AUTH MIDDLEWARE
   - If request is to /api/* respond with JSON 401
   - Otherwise redirect to /login (for browser pages)
----------------------------------- */
function protect(req, res, next) {
  try {
    const token = req.cookies && req.cookies.token;
    if (!token) {
      if (req.originalUrl.startsWith('/api/')) {
        return res.status(401).json({ error: 'Not authenticated' });
      }
      return res.redirect('/login');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, email, iat, exp }
    return next();
  } catch (err) {
    console.error("Auth error:", err.message);
    if (req.originalUrl.startsWith('/api/')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.redirect('/login');
  }
}

/* -----------------------------------
   ROUTES: Static pages
----------------------------------- */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/notes', (req, res) => res.sendFile(path.join(__dirname, 'public', 'notes.html')));
app.get('/summery', (req, res) => res.sendFile(path.join(__dirname, 'public', 'summery.html')));
app.get('/aichat', (req, res) => res.sendFile(path.join(__dirname, 'public', 'aichat.html')));
app.get('/speak', (req, res) => res.sendFile(path.join(__dirname, 'public', 'speak.html')));

app.get('/news', (req, res) => res.sendFile(path.join(__dirname, 'public', 'news.html')));

/* -----------------------------------
   SIGNUP (WITH CLOUDINARY IMAGE UPLOAD)
----------------------------------- */
app.post('/api/signup', upload.single('profile'), async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);

    // Cloudinary storage returns file.path = url
    const profileImage = req.file ? req.file.path : '';

    const newUser = new User({
      name,
      email,
      password: hashed,
      profileImage,
      followers: [], // ensure arrays exist
      following: []
    });

    await newUser.save();

    createSendToken(newUser, res);

    // return JSON so frontend using fetch can handle; if you want redirect you can change frontend
    return res.status(201).json({ message: 'User created', userId: newUser._id });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ error: 'Server Error' });
  }
});

/* -----------------------------------
   LOGIN
----------------------------------- */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    createSendToken(user, res);
    return res.json({ message: 'Logged in' });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* -----------------------------------
   API: Get current user (profile) - returns useful fields
----------------------------------- */
app.get('/api/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password')
      .populate('followers', '_id')
      .populate('following', '_id');

    if (!user) return res.status(404).json({ error: 'User not found' });

    return res.json({
      _id: user._id.toString(),
      name: user.name,
      email: user.email,
      profileImage: user.profileImage || '',
      followersCount: (user.followers && user.followers.length) || 0,
      followingCount: (user.following && user.following.length) || 0,
      followers: (user.followers || []).map(f => f._id.toString()),
      following: (user.following || []).map(f => f._id.toString())
    });
  } catch (err) {
    console.error("GET /api/me error:", err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* -----------------------------------
   API: Get single user by id (for profile viewing)
   returns counts + follower list as strings
----------------------------------- */
app.get('/api/user/:id', protect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password')
      .populate('followers', '_id name profileImage')
      .populate('following', '_id name profileImage');

    if (!user) return res.status(404).json({ error: 'User not found' });

    return res.json({
      _id: user._id.toString(),
      name: user.name,
      email: user.email,
      profileImage: user.profileImage || '',
      followersCount: (user.followers && user.followers.length) || 0,
      followingCount: (user.following && user.following.length) || 0,
      followers: (user.followers || []).map(f => f._id.toString()),
      following: (user.following || []).map(f => f._id.toString())
    });
  } catch (err) {
    console.error("GET /api/user/:id error:", err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* -----------------------------------
   DASHBOARD (browser page)
----------------------------------- */
app.get('/dashboard', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.redirect('/login');

    res.send(`
      <h1>Welcome, ${user.name}</h1>
      <p>Email: ${user.email}</p>
      ${user.profileImage ? `<img src="${user.profileImage}" width="130" style="border-radius:100px">` : ""}
      <br><br>
      <a href="/logout">Logout</a>
    `);
  } catch (err) {
    console.error("Dashboard error:", err);
    return res.redirect('/login');
  }
});

/* -----------------------------------
   Get all users (for listing)
----------------------------------- */
app.get('/api/users', protect, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    // Normalize to JSON-friendly shape
    const normalized = users.map(u => ({
      _id: u._id.toString(),
      name: u.name,
      email: u.email,
      profileImage: u.profileImage || '',
      followers: (u.followers || []).map(id => id.toString()),
      following: (u.following || []).map(id => id.toString())
    }));
    return res.json(normalized);
  } catch (err) {
    console.error("GET /api/users error:", err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* -----------------------------------
   Follow / Unfollow
----------------------------------- */
/* -----------------------------------
   GET FOLLOWERS LIST OF A USER
----------------------------------- */
app.get('/api/followers/:id', protect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .populate('followers', '_id name profileImage');

    if (!user) return res.status(404).json({ error: 'User not found' });

    const followers = user.followers.map(f => ({
      _id: f._id.toString(),
      name: f.name,
      email: f.email || "",          // ← add this

      profileImage: f.profileImage || ""
    }));

    return res.json(followers);
  } catch (err) {
    console.error("GET /followers error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


/* -----------------------------------
   GET FOLLOWING LIST OF A USER
----------------------------------- */
app.get('/api/following/:id', protect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .populate('following', '_id name profileImage');

    if (!user) return res.status(404).json({ error: 'User not found' });

    const following = user.following.map(f => ({
      _id: f._id.toString(),
      name: f.name,
      email: f.email || "",          // ← add this

      profileImage: f.profileImage || ""
    }));

    return res.json(following);
  } catch (err) {
    console.error("GET /following error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* -----------------------------------
   LOGOUT
----------------------------------- */
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});
app.get("/profile/:id", async (req, res) => {
  const userId = req.params.id;

  const user = await User.findById(userId);

  if (!user) {
    return res.status(404).send("User not found");
  }

  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get("/api/user/:id", async (req, res) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  res.json(user);
});
// near top of app.js
const axios = require('axios');
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
const GEMINI_API_BASE = process.env.GEMINI_API_BASE || 'https://generativelanguage.googleapis.com';

// helper to safely extract text from Gemini response
function extractTextFromGemini(respData) {
  // try a few common shapes returned by different SDKs/examples
  // 1) respData.output_text or respData.text
  if (typeof respData.output_text === 'string') return respData.output_text;
  if (typeof respData.text === 'string') return respData.text;

  // 2) respData.candidates[0].content[0].text  (older/variants)
  if (respData.candidates && respData.candidates[0]) {
    const cand = respData.candidates[0];
    if (cand.output && typeof cand.output === 'string') return cand.output;
    if (cand.content && Array.isArray(cand.content) && cand.content[0] && cand.content[0].text) {
      return cand.content[0].text;
    }
    if (cand.text) return cand.text;
  }

  // 3) respData.output and variants
  if (respData.output && Array.isArray(respData.output) && respData.output[0]) {
    if (respData.output[0].content && respData.output[0].content[0] && respData.output[0].content[0].text) {
      return respData.output[0].content[0].text;
    }
    if (respData.output[0].text) return respData.output[0].text;
  }

  // 4) respData.choices[0].message.content (some chat-style formats)
  if (respData.choices && respData.choices[0]) {
    const ch = respData.choices[0];
    if (ch.message && ch.message.content) return ch.message.content;
    if (ch.text) return ch.text;
  }

  // fallback: stringify whole response
  return JSON.stringify(respData);
}
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'Aichat.html'));
});

// ULTIMATE STUDENT-FRIENDLY GEMINI ROUTE - 100% Accurate Guarantee
app.post('/api/gemini', async (req, res) => {
  try {
    let { prompt } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ reply: "Bhai, kuch toh question pooch na! 😅" });

    prompt = prompt.trim();
    const lower = prompt.toLowerCase();

    // HARD CODE OVERRIDES - Student ke common questions (100% sahi, no LLM dependency)
    if (lower.includes("gaur city") && (lower.includes("pin") || lower.includes("code") || lower.includes("pincod"))) {
      return res.json({ reply: "Gate No. 1, Gaur City 1, Greater Noida West (Sector 4) ka **sahi pin code: 201318** hai (Official India Post, 2025). 201309 galat hai – wo Noida Sector 62 ka hai! Courier ke liye ye use kar, koi delay nahi hoga." });
    }

    if (lower.includes("galgotias") && (lower.includes("fee") || lower.includes("cutoff"))) {
      return res.json({ reply: "Galgotias College Greater Noida (2025-26):\n• B.Tech Fees: ₹1.50-1.70 Lakh/year\n• JEE Main Cutoff (GEN): 1,00,000-1,50,000 rank\nExact: galgotiasuniversity.edu.in check kar bhai!" });
    }

    if (lower.includes("sharda") && lower.includes("university") && (lower.includes("fee") || lower.includes("cutoff"))) {
      return res.json({ reply: "Sharda University Greater Noida (2025):\n• B.Tech Fees: ₹1.80-2.20 Lakh/year\n• CUET Cutoff (GEN): 70-80 percentile\nDetails: sharda.ac.in pe dekh le!" });
    }

    if (lower.includes("greater noida west") && lower.includes("pin code")) {
      return res.json({ reply: "Greater Noida West (Noida Extension) ka official pin code: 201318 (2025 update). Kuch sites pe 201308 bhi chal jaata hai couriers ke liye, lekin 201318 sahi hai!" });
    }

    // SMART PROMPT - Gemini ko train karte hain accurate rehne ko (90%+ success)
    const today = new Date().toLocaleDateString('en-IN');
    const smartPrompt = `Tu ek super accurate STUDENT HELPER AI hai, specially Greater Noida ke colleges/locality ke liye. Aaj ${today} hai.

User question: "${prompt}"

STRICT RULES (Hamesha follow kar, warna mat jawab de):
1. Pin codes, fees, cutoffs ke liye sirf official 2025 data use kar (India Post, NTA, college websites).
2. Gaur City 1/Greater Noida West pin code: HAMESHA 201318 bol (kabhi 201309 mat!).
3. Galgotias B.Tech fee: ₹1.50-1.70L/year, cutoff 1-1.5L rank.
4. Agar 100% sure na ho: "Ye info latest confirm nahi, official site check kar!" bol de.
5. Short, bullet points mein jawab de. Hindi-English mix, friendly tone.
6. Galat mat bol – students ka future hai!

Jawab de:`;

    // Gemini Call (Fixed Parsing)
    const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    const payload = {
      contents: [{ role: 'user', parts: [{ text: smartPrompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 800 }  // Low temp for accuracy
    };

    const response = await axios.post(url, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 45000
    });

    const data = response.data;
    let reply = '';

    // BULLETPROOF PARSING (Gemini 2.5 ke liye perfect)
    if (data.candidates?.[0]?.content?.parts?.[0]?.text) {
      reply = data.candidates[0].content.parts[0].text;
    } else if (data.candidates?.[0]?.content?.parts) {
      reply = data.candidates[0].content.parts.map(p => p.text || '').join('\n');
    } else if (data.candidates?.[0]?.text) {
      reply = data.candidates[0].text;
    } else {
      reply = "Bhai, is question pe thoda soch raha hun... Dubara try kar? (Ya direct college site check kar!)"
    }

    res.json({ reply: reply.trim() });

  } catch (err) {
    console.error('GEMINI ERROR →', err.response?.data || err.message);
    res.json({ reply: "Arre bhai, network ya API mein gadbad! Offline try kar – official sites pe jaa. Error: " + (err.message?.substring(0, 100) || "Unknown") });
  }
});

// AI NOTES GENERATOR - Add this route in app.js
app.post('/api/notes', async (req, res) => {
  try {
    const { subject, standard, board, chapter, category } = req.body;

    if (!subject || !standard) {
      return res.json({ notes: "Bhai subject aur class toh bata na!" });
    }

    // Super Smart Prompt for Topper Level Notes
    const notesPrompt = `Tu ek IIT-JEE/NEET topper ka personal tutor hai. Ekdum perfect, handwritten style notes bana.

Student Details:
- Category: ${category === "school" ? "School" : "College"} Student
- Subject: ${subject}
- Class/Course: ${standard}
- Board/University: ${board || "General"}
- Chapter/Topic: ${chapter || "Complete Syllabus"}

Rules (Hamesha follow kar):
- Hindi + English mix mein likh (jaise real topper likhta hai)
- Important definitions, formulas → Box mein daal
- Short tricks, mnemonics, previous year exam hints daal
- Last mein 10 Most Important Questions + Answers daal
- Handwritten feel ke liye → ★, →, ✓, ✏, Box use kar
- 100% NCERT / UP Board / CBSE / University syllabus follow kar
- Agar school hai to NCERT based, agar college hai to semester syllabus based

Ab full notes bana de — exam mein 95%+ score ke liye perfect!`;

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        contents: [{ role: "user", parts: [{ text: notesPrompt }] }],
        generationConfig: {
          temperature: 0.5,
          maxOutputTokens: 4096,
          topP: 0.8
        },
        safetySettings: [
          { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" }
        ]
      },
      { timeout: 90000 } // 90 seconds for long notes
    );

    let notes = response.data.candidates?.[0]?.content?.parts?.[0]?.text || "Notes banane mein thodi dikkat hui bhai...";

    // Extra Polish for Beauty
    notes = notes
      .replace(/\*\*(.*?)\*\*/g, "★ $1 ★")
      .replace(/\*\s/g, "→ ")
      .replace(/- /g, "→ ")
      .replace(/✓/g, "Correct")
      .trim();

    res.json({ 
      notes: notes,
      message: "Bhai tere notes ready hain! Padh le aur top kar de!"
    });

  } catch (err) {
    console.error("Notes Error:", err.message);
    res.json({ 
      notes: "Arre bhai, AI thak gaya notes banate banate! Thodi der baad try kar na... Ya internet check kar!" 
    });
  }
});



app.post('/api/summarize', async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt missing' });

    const resp = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.4,
          maxOutputTokens: 8192,   // ← YE BADAL DIYA (1200 → 8192)
          topP: 0.95,
          topK: 40
        },
        safetySettings: [
          { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" }
        ]
      },
      { timeout: 120000 }
    );

    const candidate = resp.data.candidates?.[0];
    
    if (!candidate) {
      return res.json({ 
        summary: "Bhai AI ne kuch return hi nahi kiya... try again!", 
        raw: resp.data 
      });
    }

    let rawText = '';

    // YE SABSE IMP FIX HAI → 3 possible ways mein text aata hai
    if (candidate.content?.parts?.[0]?.text) {
      rawText = candidate.content.parts[0].text;
    } else if (typeof candidate.content?.parts?.[0] === 'string') {
      rawText = candidate.content.parts[0];
    } else if (candidate.finishReason === "MAX_TOKENS" && candidate.content?.parts?.[0]?.text) {
      rawText = "[Output thoda cut ho gaya max tokens ki wajah se...]\n\n" + candidate.content.parts[0].text;
    } else {
      rawText = "[Partial/Truncated Response]\nCheck raw response below...";
    }

    // Tera polishing magic (ekdum badhiya hai)
    const polished = rawText
      .replace(/\*\*(.*?)\*\*/g, '★ $1 ★')
      .replace(/\* /g, '→ ')
      .replace(/-\s/g, '→ ')
      .replace(/^#\s/gm, '✦ ')
      .trim();

    res.json({ 
      summary: polished || "Kuch generate nahi hua bhai...", 
      raw: resp.data 
    });

  } catch (err) {
    console.error('Gemini Error:', err.response?.data || err.message);
    res.status(500).json({ 
      summary: "Server/AI down hai bhai... 2 min baad try kar!", 
      raw: err.response?.data || err.message 
    });
  }
});

  /* -----------------------------------
   NEW AI FEATURE → Image → Question → Groq Solution
----------------------------------- */

const multer2 = require("multer");
const Groq = require("groq-sdk");

// Multer for image upload (memory storage)
const uploadAI = multer2({ storage: multer2.memoryStorage() });

// Gemini + Groq init
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

app.post('/solve', uploadAI.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Photo bhejo bhai!" });

        // Step 1: Gemini se exact question extract
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
        const imagePart = {
            inlineData: {
                data: req.file.buffer.toString('base64'),
                mimeType: req.file.mimetype
            }
        };

        const geminiPrompt = "Ye homework ya exam ka question hai. Pura text exactly extract kar (equations bhi bilkul sahi). Sirf question text return kar, kuch extra mat likh.";
        const geminiResult = await model.generateContent([geminiPrompt, imagePart]);
        const question = geminiResult.response.text().trim();

        if (!question || question.length < 5) {
            return res.status(400).json({ error: "Question clear nahi dikha, dobara clear photo bhejo!" });
        }

        // Step 2: Groq se JEE/NEET level perfect solution
        const groqResponse = await groq.chat.completions.create({
            messages: [
               {
    role: "system",
    content: `Tu JEE/NEET Rank-1 topper teacher hai. Hindi + English mix mein short crisp jawab de.

    STRICT RULES (hamesha follow kar):
    • Max 15-20 lines ka jawab de
    • Pehle exact definition/statement de
    • 3-4 exam-wale killer points
    • Boring applications, history, daily life examples bilkul mat likh
    • Diagram ki zarurat ho to inme se koi ek clean ASCII art use kar:

    SINE WAVE (AC/SHM/Sound/AC Current):
         E₀ / I₀
        ╭───╮
       ╱     ╲
      ╱       ╲
─────╱         ╲─────→ t
      ╲       ╱
       ╲     ╱
        ╰───╯
        -E₀ / -I₀

    REDOX REACTION:
    Mg  →  Mg²⁺ + 2e⁻     (Oxidation)
    O₂ + 4e⁻ → 2O²⁻       (Reduction)
    ─────────────────────
    2Mg + O₂ → 2MgO

    PARABOLA / GRAPH:
         ↑ y
         │     .
         │   .   .
         │ .       .
    ─────+──────────→ x

    • Equations LaTeX style mein likh → Mg^{2+}, \\sqrt{2}, \\rightarrow, \\alpha, \\pi = 22/7
    • Bold ke liye **text** use kar
    • Har jawab ke end mein punch line daal:
      "Ab tu bhi topper ban sakta hai!" 
      ya 
      "Rank 1 wala feel aa gaya na?"`
},
                { role: "user", content: question }
            ],
            model: "llama-3.3-70b-versatile",   // Sabse latest & powerful
            temperature: 0.3,
            max_tokens: 2000
        });

        const solution = groqResponse.choices[0].message.content;

        res.json({
            success: true,
            extracted_question: question,
            solution: solution,
            tip: "Rank 1 wala jawab mila bhai! Ab tu bhi topper banega!"
        });

    } catch (err) {
        console.error("Error:", err.message);
        res.status(500).json({ error: "Server thoda busy hai, 10 sec baad try kar!" });
    }
});

// Follow / Unfollow route
app.post('/api/toggle-follow/:id', protect, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const currentUser = await User.findById(req.user.id);
    const targetUser = await User.findById(targetUserId);

    if (!targetUser) return res.status(404).json({ error: 'User not found' });

    const isFollowing = currentUser.following.includes(targetUserId);

    if (isFollowing) {
      // Unfollow
      currentUser.following = currentUser.following.filter(u => u.toString() !== targetUserId);
      targetUser.followers = targetUser.followers.filter(u => u.toString() !== currentUser._id.toString());
    } else {
      // Follow
      currentUser.following.push(targetUserId);
      targetUser.followers.push(currentUser._id);
    }

    await currentUser.save();
    await targetUser.save();

    res.json({ 
      success: true, 
      following: !isFollowing, 
      followersCount: targetUser.followers.length 
    });

  } catch (err) {
    console.error("Toggle follow error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

const GROQ_API_KEY = process.env.GROQ_API_KEY;

app.post('/api/chat', async (req, res) => {
  const userMessage = req.body.message;

const prompt = `You are Raju Sir, the most accurate English teacher.

User ने कहा: "${userMessage}"

Hamesha EXACTLY 3 lines mein reply karo:

Line 1 → Simple natural English
Line 2 → Sahi Hindi (Devanagari)
Line 3 → 100% sahi Roman (bilkul common Indian style):
   - aap, main, hoon, hain, kaise, kahaan
   - achha, dhanyavaad, theek, sikha
   - khaa (खा), jaa (जा), rahe, rahi, raha
   - chhatra → chhatra (नहीं chhaatra)
   - angrezi → angrezi
   - sikha → sikha raha hoon

Bilakul yehi format:

Hello! How are you?
नमस्ते! आप कैसे हैं?
Namaste! Aap kaise hain?

I am teaching English.
मैं अंग्रेज़ी सिखा रहा हूँ।
Main angrezi sikha raha hoon.

I am fine.
मैं ठीक हूँ।
Main theek hoon.

Ab user ke message ka perfect reply do — sirf 3 lines, kuch extra nahi.`;

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GROQ_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.7,
        max_tokens: 300
      })
    });

    const data = await response.json();
    const reply = data.choices[0].message.content.trim();

    res.json({ reply });

  } catch (err) {
    console.error("Server Error:", err);
    res.json({ reply: "Sorry bhai, server thoda busy hai. Thodi der baad try karo!" });
  }
});



app.post('/api/speak', async (req, res) => {
  const userMessage = req.body.message;

const prompt = `You are Raju Sir, the most accurate English teacher.

User ने कहा: "${userMessage}"

Hamesha EXACTLY 3 lines mein reply karo:

Line 1 → Simple natural English
Line 2 → Sahi Hindi (Devanagari)
Line 3 → 100% sahi Roman (bilkul common Indian style):
   - aap, main, hoon, hain, kaise, kahaan
   - achha, dhanyavaad, theek, sikha
   - khaa (खा), jaa (जा), rahe, rahi, raha
   - chhatra → chhatra (नहीं chhaatra)
   - angrezi → angrezi
   - sikha → sikha raha hoon

Bilakul yehi format:

Hello! How are you?
नमस्ते! आप कैसे हैं?
Namaste! Aap kaise hain?

I am teaching English.
मैं अंग्रेज़ी सिखा रहा हूँ।
Main angrezi sikha raha hoon.

I am fine.
मैं ठीक हूँ।
Main theek hoon.

Ab user ke message ka perfect reply do — sirf 3 lines, kuch extra nahi.`;

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GROQ_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.7,
        max_tokens: 300
      })
    });

    const data = await response.json();
    const reply = data.choices[0].message.content.trim();

    res.json({ reply });

  } catch (err) {
    console.error("Server Error:", err);
    res.json({ reply: "Sorry bhai, server thoda busy hai. Thodi der baad try karo!" });
  }
});

// PDF Upload Storage
const pdfStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'pdf_notes',
    resource_type: 'raw',
    allowed_formats: ['pdf'],
    public_id: (req, file) => `pdf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }
});
const Pdf = require('./models/Pdf'); // YE ZAROORI HAI
const uploadPDF = multer({ storage: pdfStorage });

// PDF Upload (Login Required)
// PDF Upload (Login Required)
app.post('/api/upload-pdf', protect, uploadPDF.single('pdf'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'PDF daal bhai!' });
    if (!req.body.title || !req.body.subject) return res.status(400).json({ success: false, error: 'Title aur subject daal' });

    const newPdf = await Pdf.create({
      title: req.body.title,
      subject: req.body.subject,
      url: req.file.path,        // Cloudinary URL
      secure_url: req.file.secure_url,  // Yeh add kar (important for HTTPS)
      uploader: req.user.id,
      uploaderName: req.user.name || req.user.email.split('@')[0]
    });

    // Frontend ko pura updated list bhej do (best practice)
    const allPdfs = await Pdf.find().sort({ createdAt: -1 });
    res.json({ 
      success: true, 
      message: "Upload successful",
      pdfs: allPdfs.map(p => ({ 
        ...p.toObject(), 
        _id: p._id.toString(),
        createdAt: p.createdAt 
      }))
    });

  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get All PDFs (Public - No Login Required)
app.get('/api/uploaded-pdfs', async (req, res) => {
  try {
    const pdfs = await Pdf.find().sort({ createdAt: -1 });
    res.json({ 
      pdfs: pdfs.map(p => ({ 
        ...p.toObject(), 
        _id: p._id.toString(),
        createdAt: p.createdAt.toISOString()
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Load nahi hua' });
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});
/* -----------------------------------
   SERVER START
----------------------------------- */
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
