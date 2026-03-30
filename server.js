/**
 * server.js — Backend Express pour le portfolio de Reda HINA
 * Proxy sécurisé vers l'API Anthropic Claude
 * La clé API ne transite JAMAIS côté client
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Vérification au démarrage ───────────────────────────────────────────────
if (!process.env.ANTHROPIC_API_KEY) {
  console.error('\n❌ ERREUR : ANTHROPIC_API_KEY est manquante dans le fichier .env');
  console.error('   Copiez .env.example → .env et ajoutez votre clé.\n');
  process.exit(1);
}

// ─── Middlewares ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '16kb' }));   // Limite la taille des requêtes

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*', // En prod : mettez votre domaine exact
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

// Rate limiting maison — 10 requêtes/min par IP sur /api/generate-veille
const rateLimitMap = new Map();
function rateLimit(req, res, next) {
  const ip  = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 60_000;    // 1 minute
  const maxRequests = 10;

  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, startTime: now });
    return next();
  }

  const record = rateLimitMap.get(ip);

  if (now - record.startTime > windowMs) {
    // Fenêtre expirée → on repart à zéro
    rateLimitMap.set(ip, { count: 1, startTime: now });
    return next();
  }

  if (record.count >= maxRequests) {
    const retryAfter = Math.ceil((windowMs - (now - record.startTime)) / 1000);
    res.set('Retry-After', retryAfter);
    return res.status(429).json({
      error: `Trop de requêtes. Réessayez dans ${retryAfter} secondes.`,
    });
  }

  record.count++;
  next();
}

// Headers de sécurité HTTP
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options':  'nosniff',
    'X-Frame-Options':         'DENY',
    'X-XSS-Protection':        '1; mode=block',
    'Referrer-Policy':         'strict-origin-when-cross-origin',
  });
  next();
});

// ─── Fichiers statiques (le front) ───────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Endpoint : génération de veille ─────────────────────────────────────────
app.post('/api/generate-veille', rateLimit, async (req, res) => {
  const prompt = `Tu es un expert en cybersécurité. Génère un article de veille technologique \
court (environ 150 mots) en français sur UNE avancée récente et concrète de l'IA \
dans la cybersécurité (ex: détection de menaces, SOC automatisé, attaques IA, LLM sécurité, etc.).

Format de réponse UNIQUEMENT :
TITRE: [titre de l'article]
CATÉGORIE: [catégorie]
CONTENU: [article en 3-4 paragraphes concis et informatifs]

Pas de markdown, pas de balises, juste ce format exact.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':    'application/json',
        'x-api-key':       process.env.ANTHROPIC_API_KEY,   // ← clé JAMAIS envoyée au client
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 800,
        messages:   [{ role: 'user', content: prompt }],
      }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      console.error('Anthropic API error:', response.status, err);
      return res.status(502).json({ error: 'Erreur lors de la communication avec Claude.' });
    }

    const data  = await response.json();
    const text  = data.content?.[0]?.text ?? '';

    // Parser la réponse structurée
    const titleMatch   = text.match(/TITRE:\s*(.+)/);
    const catMatch     = text.match(/CATÉGORIE:\s*(.+)/);
    const contentMatch = text.match(/CONTENU:\s*([\s\S]+)/);

    return res.json({
      title:   titleMatch?.[1]?.trim()   ?? 'Mise à jour de veille',
      category: catMatch?.[1]?.trim()    ?? 'IA & Cybersécurité',
      content:  contentMatch?.[1]?.trim() ?? text,
      generatedAt: new Date().toISOString(),
    });

  } catch (err) {
    console.error('Erreur serveur generate-veille:', err);
    return res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// ─── Fallback SPA (toute route inconnue → index.html) ────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Démarrage ────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Serveur démarré sur http://localhost:${PORT}`);
  console.log(`   Endpoint veille : POST http://localhost:${PORT}/api/generate-veille\n`);
});