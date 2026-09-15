/**
 * Sentinel Visitor Tracking — Privacy by Design (RGPD/CNIL)
 *
 * Désactivé par défaut.
 * Aucune donnée collectée sans consentement explicite.
 *
 * Schéma PocketBase (collection : visiteurs_sentinel) :
 *   consent_security : boolean
 *   consent_analytics: boolean
 *
 *   Si security === true :
 *     device_type : "mobile" | "tablet" | "desktop"
 *
 *   Si analytics === true :
 *     page_visitee  : string (chemin, sans paramètres ni hash)
 *     referent_brut : string (domaine uniquement, ex: "google.com")
 *     langue_brut   : string (ex: "fr-FR")
 *
 * Non collecté :
 *   - Adresse IP complète
 *   - Coordonnées GPS
 *   - Fingerprint navigateur
 *   - RAM, CPU, plugins
 *   - Paramètres d'URL contenant des données personnelles
 *
 * Durée de conservation : 90 jours (purge automatique dans SentinelReport).
 *
 * Règles PocketBase requises :
 *   createRule : "" (création publique, champs limités côté serveur)
 *   listRule   : "@request.auth.role = \"admin\""
 *   viewRule   : "@request.auth.role = \"admin\""
 *   updateRule : "@request.auth.role = \"admin\""
 *   deleteRule : "@request.auth.role = \"admin\""
 */

import { pb } from '../lib/pocketbase.js';

// ── État du consentement (session) ──────────────────────────────────────────
let _consent   = { security: false, analytics: false };
let _tracked   = false;

/**
 * Définir le consentement pour cette session.
 * Appeler avant trackVisitor().
 *
 * @param {boolean} value
 * @param {"security"|"analytics"|"all"} category
 */
export function setTrackingConsent(value, category = "all") {
  if (category === "all") {
    _consent.security  = Boolean(value);
    _consent.analytics = Boolean(value);
  } else if (category === "security" || category === "analytics") {
    _consent[category] = Boolean(value);
  }
  // Si refus total, réinitialiser le garde contre double appel
  if (!_consent.security && !_consent.analytics) {
    _tracked = false;
  }
}

/**
 * Lire le consentement actuel.
 * @returns {{ security: boolean, analytics: boolean }}
 */
export function getTrackingConsent() {
  return { ..._consent };
}

// ── Utilitaires ─────────────────────────────────────────────────────────────
function getDeviceType() {
  if (!navigator.maxTouchPoints) return "desktop";
  return window.innerWidth < 768 ? "mobile" : "tablet";
}

function getSafeReferrer() {
  try {
    if (!document.referrer) return "direct";
    const url = new URL(document.referrer);
    return url.hostname.replace(/^www\./, "").slice(0, 50);
  } catch {
    return "direct";
  }
}

/**
 * Enregistrer la visite selon le consentement actif.
 *
 * N'enregistre rien si les deux catégories sont refusées.
 * Silencieux en cas d'erreur réseau — le suivi n'est jamais bloquant.
 *
 * @param {{ security?: boolean, analytics?: boolean }} [overrideConsent]
 */
export async function trackVisitor(overrideConsent) {
  const consent = overrideConsent ?? _consent;
  const { security, analytics } = consent;

  if (_tracked) return;
  if (!security && !analytics) return;
  _tracked = true;

  try {
    const payload = {
      consent_security:  Boolean(security),
      consent_analytics: Boolean(analytics),
    };

    if (security) {
      payload.device_type = getDeviceType();
    }

    if (analytics) {
      payload.page_visitee  = window.location.pathname.slice(0, 100);
      payload.referent_brut = getSafeReferrer();
      payload.langue_brut   = (navigator.language || "").slice(0, 10) || "?";
    }

    await pb.collection("visiteurs_sentinel").create(payload);
  } catch {
    // Silencieux — erreur réseau non critique
    _tracked = false; // permettre un retry si l'erreur est transitoire
  }
}

/**
 * Réinitialiser l'état de suivi (utile pour les tests ou la déconnexion).
 */
export function resetTracking() {
  _tracked = false;
  _consent = { security: false, analytics: false };
}
