/**
 * Sentinel Visitor Tracking
 * Enregistre chaque connexion : IP + localisation chiffrées (AES-GCM)
 * Seul l'admin peut déchiffrer (clé stockée dans AdminPanel, jamais exposée)
 */
import { pb } from '/usr/lib/sfs-assistant-dev/pocketbase.js';

// Provide SENTINEL_AES_KEY_HEX through the host application's runtime config.
// Never commit a real key. The integration must fail closed when it is absent.
const AES_KEY_HEX = globalThis.SENTINEL_AES_KEY_HEX || "";

// ── Utilitaires crypto ──────────────────────────────────────────────────────
async function getKey() {
  if (!/^[0-9a-fA-F]{64}$/.test(AES_KEY_HEX)) {
    throw new Error("SENTINEL_AES_KEY_HEX must be a 64-character hexadecimal key");
  }
  const raw = new Uint8Array(AES_KEY_HEX.match(/.{2}/g).map(h => parseInt(h, 16)));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encrypt(text) {
  const key = await getKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `${toHex(iv)}:${toHex(cipher)}`;
}

// ── SHA-256 de l'IP pour identification sans stockage en clair ──────────────
async function hashIP(ip) {
  const encoded = new TextEncoder().encode(ip + "_sentinel_salt_2026");
  const buf = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

// ── Récupère l'IP publique du visiteur ─────────────────────────────────────
async function getPublicIP() {
  try {
    const r = await fetch("https://api.ipify.org?format=json");
    const d = await r.json();
    return d.ip || "unknown";
  } catch {
    return "unknown";
  }
}

// ── Récupère la géolocalisation IP ─────────────────────────────────────────
async function getGeo(ip) {
  try {
    const r = await fetch(`https://ipapi.co/${ip}/json/`);
    const d = await r.json();
    return {
      pays: d.country_name || "?",
      pays_code: d.country_code || "?",
      ville: d.city || "?",
      region: d.region || "?",
      timezone: d.timezone || "?",
      org: d.org || "?",            // FAI / organisation réseau
      lat: d.latitude || 0,
      lon: d.longitude || 0,
    };
  } catch {
    return { pays: "?", pays_code: "?", ville: "?", region: "?", timezone: "?", org: "?", lat: 0, lon: 0 };
  }
}

// ── Empreinte navigateur (sans bibliothèque tierce) ──────────────────────────
function getBrowserFingerprint() {
  const nav = navigator;
  const screen = window.screen;
  return {
    // Navigateur & moteur
    userAgent: nav.userAgent,
    language: nav.language,
    languages: (nav.languages || []).join(","),
    platform: nav.platform || "?",
    vendor: nav.vendor || "?",
    cookiesEnabled: nav.cookieEnabled,
    doNotTrack: nav.doNotTrack || "?",

    // Écran & fenêtre
    screenWidth: screen.width,
    screenHeight: screen.height,
    screenDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio || 1,
    windowWidth: window.innerWidth,
    windowHeight: window.innerHeight,
    orientation: screen.orientation ? screen.orientation.type : "?",

    // Timezone
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),

    // Capacités matérielles
    hardwareConcurrency: nav.hardwareConcurrency || "?",
    deviceMemory: nav.deviceMemory || "?",
    maxTouchPoints: nav.maxTouchPoints || 0,

    // Type d'appareil
    deviceType: nav.maxTouchPoints > 0
      ? (window.innerWidth < 768 ? "mobile" : "tablet")
      : "desktop",

    // Plugins (liste noms seulement)
    plugins: Array.from(nav.plugins || []).map(p => p.name).join("|").slice(0, 200),
  };
}

// ── Référent & navigation ────────────────────────────────────────────────────
function getNavigationInfo() {
  return {
    referrer: document.referrer || "direct",
    page: window.location.pathname,
    hash: window.location.hash || "",
    queryParams: window.location.search ? window.location.search.slice(0, 100) : "",
    entryTime: new Date().toISOString(),
  };
}

// ── Point d'entrée principal — appelé une fois par session ──────────────────
const CONSENT_STORAGE_KEY = "sentinel_tracking_consent";

export function hasTrackingConsent() {
  try { return globalThis.localStorage?.getItem(CONSENT_STORAGE_KEY) === "granted"; } catch { return false; }
}

export function setTrackingConsent(granted) {
  try {
    if (granted) globalThis.localStorage?.setItem(CONSENT_STORAGE_KEY, "granted");
    else globalThis.localStorage?.removeItem(CONSENT_STORAGE_KEY);
  } catch {}
}

let _tracked = false;

export async function trackVisitor() {
  // Privacy by default: never collect without explicit, prior consent.
  if (!hasTrackingConsent() || _tracked) return;
  _tracked = true;

  try {
    const ip = await getPublicIP();
    const geo = await getGeo(ip);
    const fingerprint = getBrowserFingerprint();
    const navInfo = getNavigationInfo();

    // Données brutes à chiffrer
    const ipData = JSON.stringify({ ip, hash: await hashIP(ip) });
    const geoData = JSON.stringify(geo);
    const fingerprintData = JSON.stringify(fingerprint);
    const navData = JSON.stringify(navInfo);

    // Chiffrement AES-GCM de tout
    const [ip_chiffree, localisation_chiffree, empreinte_chiffree, navigation_chiffree] = await Promise.all([
      encrypt(ipData),
      encrypt(geoData),
      encrypt(fingerprintData),
      encrypt(navData),
    ]);

    await pb.collection("visiteurs_sentinel").create({
      ip_chiffree,
      localisation_chiffree,
      empreinte_chiffree,
      navigation_chiffree,
      pays_brut: geo.pays,
      user_agent: navigator.userAgent.slice(0, 500),
      page_visitee: window.location.pathname,
      referent_brut: document.referrer ? document.referrer.slice(0, 200) : "direct",
      device_type: fingerprint.deviceType,
      langue_brut: navigator.language || "?",
    });
  } catch {
    // Silencieux — tracking non critique
  }
}

// ── Déchiffrement (admin uniquement) ─────────────────────────────────────────
export async function decryptField(encryptedHex) {
  try {
    const [ivHex, cipherHex] = encryptedHex.split(":");
    const fromHex = (h) => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));
    const key = await getKey();
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromHex(ivHex) },
      key,
      fromHex(cipherHex)
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch {
    return null;
  }
}

