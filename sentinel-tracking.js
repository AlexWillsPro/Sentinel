/**
 * Sentinel Visitor Tracking
 *
 * Privacy by default:
 * - aucune collecte tant qu'un consentement explicite n'a pas été donné ;
 * - aucun accès à l'adresse IP, aucune géolocalisation IP et aucun fingerprinting ;
 * - les catégories de consentement sont indépendantes ;
 * - les données d'identité (nom, prénom, e-mail) ne sont jamais récupérées ici.
 *
 * Les données de contact doivent provenir d'un formulaire distinct, rempli
 * volontairement par l'utilisateur pour une finalité clairement annoncée.
 */
import { pb } from '/usr/lib/sfs-assistant-dev/pocketbase.js';

const CONSENT_STORAGE_KEY = "sentinel_tracking_consent_v2";

const DEFAULT_CONSENT = Object.freeze({
  security: false,
  analytics: false,
});

function normalizeConsent(value = {}) {
  return {
    security: value.security === true,
    analytics: value.analytics === true,
  };
}

/**
 * Retourne les choix de consentement enregistrés localement.
 * En cas d'absence, d'erreur ou de valeur invalide, tout reste désactivé.
 */
export function getTrackingConsent() {
  try {
    const raw = globalThis.localStorage?.getItem(CONSENT_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_CONSENT };
    return normalizeConsent(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_CONSENT };
  }
}

/**
 * Enregistre des choix explicites par catégorie.
 * Exemple : setTrackingConsent({ security: true, analytics: false })
 */
export function setTrackingConsent(consent = {}) {
  const normalized = normalizeConsent(consent);
  try {
    globalThis.localStorage?.setItem(CONSENT_STORAGE_KEY, JSON.stringify(normalized));
  } catch {}
  return normalized;
}

/** Révoque l'ensemble des consentements facultatifs. */
export function revokeTrackingConsent() {
  try {
    globalThis.localStorage?.removeItem(CONSENT_STORAGE_KEY);
  } catch {}
}

/** Compatibilité simple : vrai si au moins une catégorie est autorisée. */
export function hasTrackingConsent() {
  const consent = getTrackingConsent();
  return consent.security || consent.analytics;
}

function getDeviceType() {
  const width = globalThis.innerWidth || 0;
  const touch = navigator.maxTouchPoints || 0;
  if (touch > 0 && width < 768) return "mobile";
  if (touch > 0) return "tablet";
  return "desktop";
}

function safePathname() {
  // Ne collecte ni query string ni hash afin d'éviter la récupération
  // accidentelle de jetons, identifiants ou autres données personnelles.
  return globalThis.location?.pathname || "/";
}

function safeReferrerOrigin() {
  if (!document.referrer) return "direct";
  try {
    return new URL(document.referrer).origin;
  } catch {
    return "external";
  }
}

let _tracked = false;

/**
 * Enregistre au maximum une entrée par chargement de page.
 *
 * security : données minimales utiles au tableau de sécurité
 * analytics: page, origine du référent et langue
 *
 * Refus total => aucun appel PocketBase et aucune collecte.
 */
export async function trackVisitor() {
  const consent = getTrackingConsent();
  if ((!consent.security && !consent.analytics) || _tracked) return;

  _tracked = true;

  const record = {
    consent_security: consent.security,
    consent_analytics: consent.analytics,
  };

  if (consent.security) {
    record.device_type = getDeviceType();
  }

  if (consent.analytics) {
    record.page_visitee = safePathname();
    record.referent_brut = safeReferrerOrigin();
    record.langue_brut = navigator.language || "?";
  }

  try {
    await pb.collection("visiteurs_sentinel").create(record);
  } catch (error) {
    // Le tracking est non critique. L'application hôte peut brancher son propre
    // logger ici, sans inclure de données personnelles dans les journaux.
    if (globalThis.SENTINEL_DEBUG === true) {
      console.warn("Sentinel tracking unavailable", error?.message || "unknown error");
    }
  }
}
