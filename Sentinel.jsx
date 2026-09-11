import { useState, useEffect, useRef } from "react";
import { getThreatLog, getThreatCount } from "./security.js";
import { getAuditLog, detectAnomalies } from './api/api-key-manager.js';
import { pb } from '/usr/lib/sfs-assistant-dev/pocketbase.js';
// decryptField supprimé — données minimales uniquement, conformité RGPD

const AGENTS = [
  {
    id: "GHOST",
    icon: "👁",
    color: "#00eeff",
    shift: "00:00 — 08:00",
    role_fr: "Surveillance réseau & vol de clés API",
    role_en: "Network surveillance & API key theft prevention",
    patrol_fr: ["Scan du trafic entrant…", "Aucun vol de clé détecté.", "Tentatives d'accès DB : 0", "Périmètre sécurisé."],
    patrol_en: ["Scanning incoming traffic…", "No API key theft detected.", "DB access attempts: 0", "Perimeter secured."],
  },
  {
    id: "VIPER",
    icon: "🛡",
    color: "#00ff88",
    shift: "08:00 — 16:00",
    role_fr: "Protection des données utilisateur & chiffrement",
    role_en: "User data protection & encryption",
    patrol_fr: ["Vérification des accès…", "Tentatives d'extraction : 0", "Données chiffrées OK.", "Isolement DB confirmé."],
    patrol_en: ["Checking access…", "Data extraction attempts: 0", "Encryption verified.", "DB isolation confirmed."],
  },
  {
    id: "CIPHER",
    icon: "🔐",
    color: "#f7931a",
    shift: "16:00 — 24:00",
    role_fr: "Détection de requêtes malveillantes & commandes",
    role_en: "Malicious request & command injection detection",
    patrol_fr: ["Analyse comportementale…", "Injections détectées : 0", "Requêtes suspectes : 0", "Système sain."],
    patrol_en: ["Behavioral analysis…", "Injections detected: 0", "Suspicious requests: 0", "System healthy."],
  },
];

function getCurrentAgent() {
  const h = new Date().getHours();
  if (h < 8) return AGENTS[0];
  if (h < 16) return AGENTS[1];
  return AGENTS[2];
}

// ── Badge device type ────────────────────────────────────────────────────────
function DeviceBadge({ type, color }) {
  const icons = { mobile: "📱", tablet: "📟", desktop: "🖥" };
  const icon = icons[type] || "💻";
  return (
    <span style={{ fontFamily: "'Courier New', monospace", fontSize: "8px", color, opacity: 0.7 }}>
      {icon} {type || "?"}
    </span>
  );
}

// ── Ligne de donnée avec label ────────────────────────────────────────────────
function DataRow({ label, value, color, mono }) {
  if (!value || value === "?" || value === "") return null;
  return (
    <div style={{ display: "flex", gap: "6px", marginBottom: "2px", flexWrap: "wrap" }}>
      <span style={{ ...mono, fontSize: "7px", color: "rgba(255,255,255,0.25)", minWidth: "60px", flexShrink: 0 }}>{label}</span>
      <span style={{ ...mono, fontSize: "7px", color, wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

function VisiteursTab({ lang, agent }) {
  const [visiteurs, setVisiteurs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const mono = { fontFamily: "'Courier New', monospace" };

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    pb.collection("visiteurs_sentinel")
      .getList(1, 50, { sort: "-created", signal: controller.signal })
      .then((res) => {
        setVisiteurs(res.items);
        setLoading(false);
      })
      .catch((e) => { if (!e?.isAbort) setLoading(false); });
    return () => controller.abort();
  }, []);

  if (loading) return (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <span style={{ ...mono, fontSize: "9px", color: "rgba(0,255,136,0.5)", letterSpacing: "0.2em" }}>
        {lang === "en" ? "DECRYPTING…" : "DÉCHIFFREMENT…"}
      </span>
    </div>
  );

  if (visiteurs.length === 0) return (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <span style={{ ...mono, fontSize: "9px", color: "rgba(255,255,255,0.3)", letterSpacing: "0.15em" }}>
        {lang === "en" ? "No visitors recorded yet" : "Aucun visiteur enregistré"}
      </span>
    </div>
  );

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "10px 12px" }}>
      {/* Compteur global */}
      <div style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.2)", letterSpacing: "0.15em", marginBottom: "10px", textAlign: "right" }}>
        {visiteurs.length} {lang === "en" ? "visitors tracked" : "visiteurs enregistrés"}
      </div>

      {visiteurs.map((v, i) => {
        const date = v.created ? new Date(v.created).toLocaleString("fr-FR") : "?";
        const isOpen = expanded === v.id;

        return (
          <div key={v.id} style={{ marginBottom: "8px", border: `1px solid ${isOpen ? agent.color + "44" : agent.color + "18"}`, borderRadius: "2px", overflow: "hidden", transition: "border-color 0.15s" }}>

            <div
              onClick={() => setExpanded(isOpen ? null : v.id)}
              style={{ padding: "8px 10px", background: isOpen ? `${agent.color}10` : `${agent.color}06`, cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}
            >
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "3px", flexWrap: "wrap" }}>
                  <span style={{ ...mono, fontSize: "9px", color: agent.color, fontWeight: "900" }}>#{visiteurs.length - i}</span>
                  <span style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.6)" }}>{v.pays_brut || "?"}</span>
                  {v.device_type && <DeviceBadge type={v.device_type} color={agent.color} />}
                  <span style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.35)" }}>{v.page_visitee || "/"}</span>
                </div>
                <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                  <span style={{ ...mono, fontSize: "7px", color: "rgba(255,255,255,0.2)" }}>{date}</span>
                  {v.langue_brut && v.langue_brut !== "?" && <span style={{ ...mono, fontSize: "7px", color: "rgba(255,255,255,0.2)" }}>🌐 {v.langue_brut}</span>}
                  {v.referent_brut && v.referent_brut !== "direct" && <span style={{ ...mono, fontSize: "7px", color: "#ffd700aa" }}>↩ {v.referent_brut}</span>}
                </div>
              </div>
              <span style={{ ...mono, fontSize: "9px", color: `${agent.color}66`, marginLeft: "8px" }}>{isOpen ? "▲" : "▼"}</span>
            </div>

            {isOpen && (
              <div style={{ padding: "10px 12px", background: "rgba(0,0,0,0.4)", borderTop: `1px solid ${agent.color}18` }}>
                <DataRow label="Pays" value={v.pays_brut} color="rgba(255,255,255,0.5)" mono={mono} />
                <DataRow label="Appareil" value={v.device_type} color={agent.color} mono={mono} />
                <DataRow label="Langue" value={v.langue_brut} color="rgba(255,255,255,0.4)" mono={mono} />
                <DataRow label="Page" value={v.page_visitee || "/"} color="rgba(255,255,255,0.4)" mono={mono} />
                <DataRow label="Référent" value={v.referent_brut !== "direct" ? v.referent_brut : null} color="#ffd700" mono={mono} />
                <DataRow label="ID anonyme" value={v.ip_hash ? v.ip_hash.slice(0, 12) + "…" : null} color="rgba(255,255,255,0.25)" mono={mono} />
                <div style={{ ...mono, fontSize: "7px", color: "rgba(255,255,255,0.15)", marginTop: "8px", lineHeight: 1.5 }}>
                  ⚠ IP complète non stockée — identifiant anonyme mensuel uniquement (RGPD)
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function PatrolTab({ lang, agent, patrolLines, patrolLine, threats, threatCount, timeStr }) {
  const mono = { fontFamily: "'Courier New', monospace" };
  return (
    <>
      {/* Agent de garde */}
      <div style={{ padding: "12px 14px", borderBottom: `1px solid ${agent.color}11` }}>
        <div style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.25)", letterSpacing: "0.2em", marginBottom: "8px" }}>
          {lang === "en" ? "ON DUTY" : "EN SERVICE"}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{ fontSize: "22px", filter: `drop-shadow(0 0 6px ${agent.color})` }}>{agent.icon}</span>
          <div>
            <div style={{ ...mono, fontSize: "13px", fontWeight: "900", color: agent.color, letterSpacing: "0.2em" }}>{agent.id}</div>
            <div style={{ ...mono, fontSize: "9px", color: "rgba(255,255,255,0.4)" }}>
              {lang === "en" ? agent.role_en : agent.role_fr}
            </div>
            <div style={{ ...mono, fontSize: "8px", color: `${agent.color}88`, marginTop: "2px" }}>
              {lang === "en" ? "Shift:" : "Garde :"} {agent.shift}
            </div>
          </div>
        </div>
      </div>

      {/* Heure & ronde en cours */}
      <div style={{ padding: "10px 14px", borderBottom: `1px solid ${agent.color}11` }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
          <span style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.25)", letterSpacing: "0.2em" }}>
            {lang === "en" ? "PATROL LOG" : "JOURNAL DE RONDE"}
          </span>
          <span style={{ ...mono, fontSize: "9px", color: agent.color }}>{timeStr}</span>
        </div>
        <div style={{ ...mono, fontSize: "10px", color: agent.color, padding: "6px 8px", background: `${agent.color}08`, border: `1px solid ${agent.color}22`, minHeight: "28px", display: "flex", alignItems: "center" }}>
          <span style={{ color: `${agent.color}60`, marginRight: "6px" }}>›</span>
          {patrolLines[patrolLine]}
          <span style={{ animation: "blink 1s step-end infinite", marginLeft: "2px", color: agent.color }}>_</span>
        </div>
      </div>

      {/* Statut 3 agents */}
      <div style={{ padding: "10px 14px", borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
        <div style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.25)", letterSpacing: "0.2em", marginBottom: "8px" }}>
          {lang === "en" ? "TEAM STATUS" : "STATUT ÉQUIPE"}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
          {AGENTS.map(a => {
            const isActive = a.id === agent.id;
            return (
              <div key={a.id} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "12px", opacity: isActive ? 1 : 0.4 }}>{a.icon}</span>
                <span style={{ ...mono, fontSize: "9px", fontWeight: isActive ? "900" : "400", color: isActive ? a.color : "rgba(255,255,255,0.25)", letterSpacing: "0.1em", flex: 1 }}>{a.id}</span>
                <span style={{ ...mono, fontSize: "8px", color: isActive ? "#00ff88" : "rgba(255,255,255,0.2)", letterSpacing: "0.1em" }}>
                  {isActive ? (lang === "en" ? "● ON DUTY" : "● EN GARDE") : (lang === "en" ? "○ STANDBY" : "○ EN ATTENTE")}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Menaces */}
      <div style={{ padding: "10px 14px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
          <span style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.25)", letterSpacing: "0.2em" }}>
            {lang === "en" ? "THREATS BLOCKED" : "MENACES BLOQUÉES"}
          </span>
          <span style={{ ...mono, fontSize: "11px", fontWeight: "900", color: threatCount > 0 ? "#ff4444" : "#00ff88" }}>
            {threatCount}
          </span>
        </div>
        {threats.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "3px", maxHeight: "80px", overflowY: "auto" }}>
            {threats.slice(-3).map((t, i) => (
              <div key={i} style={{ ...mono, fontSize: "9px", color: "rgba(255,68,68,0.7)", padding: "2px 6px", background: "rgba(255,0,0,0.05)", border: "1px solid rgba(255,68,68,0.1)" }}>
                ⚠ {t.type || "Menace"} — {t.field || "formulaire"}
              </div>
            ))}
          </div>
        ) : (
          <div style={{ ...mono, fontSize: "9px", color: "rgba(0,255,136,0.5)", letterSpacing: "0.1em" }}>
            {lang === "en" ? "✓ All clear — no threats detected" : "✓ Aucune menace détectée"}
          </div>
        )}
      </div>
    </>
  );
}

export default function Sentinel({ lang = "fr" }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState("patrol");
  const [patrolLine, setPatrolLine] = useState(0);
  const [cameraOn, setCameraOn] = useState(true);
  const [threats, setThreats] = useState([]);
  const [threatCount, setThreatCount] = useState(0);
  const [tick, setTick] = useState(0);
  const patrolRef = useRef(null);
  const mono = { fontFamily: "'Courier New', monospace" };
  const agent = getCurrentAgent();

  useEffect(() => {
    const t = setInterval(() => setCameraOn(c => !c), 1400);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const t = setInterval(() => setTick(x => x + 1), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!open) return;
    try { setThreats(getThreatLog() || []); setThreatCount(getThreatCount() || 0); } catch {}
  }, [open, tick]);

  useEffect(() => {
    if (!open) return;
    const lines = lang === "en" ? agent.patrol_en : agent.patrol_fr;
    patrolRef.current = setInterval(() => {
      setPatrolLine(i => (i + 1) % lines.length);
    }, 3000);
    return () => clearInterval(patrolRef.current);
  }, [open, agent.id, lang]);

  const now = new Date();
  const timeStr = now.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const patrolLines = lang === "en" ? agent.patrol_en : agent.patrol_fr;

  return (
    <>
      {/* Indicateur caméra */}
      <div
        style={{ position: "fixed", top: "110px", right: "16px", zIndex: 9980, display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}
        onClick={() => setOpen(o => !o)}
        title={lang === "en" ? "SENTINEL Security Team" : "Équipe Sécurité SENTINEL"}
      >
        <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: cameraOn ? "#ff0000" : "#440000", boxShadow: cameraOn ? "0 0 8px #ff0000, 0 0 16px #ff000088" : "none", transition: "all 0.3s" }} />
        <span style={{ ...mono, fontSize: "9px", color: "rgba(255,50,50,0.7)", letterSpacing: "0.2em" }}>CAM</span>
      </div>

      {open && (
        <>
          <div style={{ position: "fixed", inset: 0, zIndex: 9990, background: "rgba(0,0,0,0.5)", pointerEvents: "auto" }} onClick={() => setOpen(false)} />
          <div style={{ position: "fixed", bottom: "max(80px, 5vh)", right: "max(20px, 2vw)", zIndex: 9991, width: "clamp(340px, 92vw, 520px)", height: "clamp(480px, 82vh, 720px)", maxHeight: "calc(100vh - 100px)", background: "rgba(0,0,0,0.97)", border: `1px solid ${agent.color}44`, boxShadow: `0 0 40px ${agent.color}33`, backdropFilter: "blur(12px)", borderRadius: "4px", overflow: "hidden", display: "flex", flexDirection: "column" }}>

            {/* Header */}
            <div style={{ padding: "10px 14px", borderBottom: `1px solid ${agent.color}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: cameraOn ? "#ff0000" : "#440000", boxShadow: cameraOn ? "0 0 8px #ff0000" : "none", transition: "all 0.3s", flexShrink: 0 }} />
                <span style={{ ...mono, fontSize: "10px", fontWeight: "900", color: agent.color, letterSpacing: "0.25em" }}>SENTINEL</span>
                <span style={{ ...mono, fontSize: "8px", color: "rgba(255,255,255,0.3)", letterSpacing: "0.1em" }}>{lang === "en" ? "SECURITY" : "SÉCURITÉ"}</span>
              </div>
              <button onClick={() => setOpen(false)} style={{ background: "transparent", border: "none", color: "rgba(255,255,255,0.3)", cursor: "pointer", fontSize: "12px" }}>✕</button>
            </div>

            {/* Onglets */}
            <div style={{ display: "flex", borderBottom: `1px solid ${agent.color}22`, flexShrink: 0 }}>
              {[
                { id: "patrol", label: lang === "en" ? "PATROL" : "PATROUILLE" },
                { id: "visiteurs", label: lang === "en" ? "VISITORS" : "VISITEURS" },
              ].map(t => (
                <button key={t.id} onClick={() => setTab(t.id)} style={{ flex: 1, padding: "8px", background: tab === t.id ? `${agent.color}18` : "transparent", border: "none", borderBottom: tab === t.id ? `2px solid ${agent.color}` : "2px solid transparent", color: tab === t.id ? agent.color : "rgba(255,255,255,0.3)", cursor: "pointer", fontFamily: "'Courier New', monospace", fontSize: "9px", fontWeight: "900", letterSpacing: "0.2em", transition: "all 0.15s" }}>{t.label}</button>
              ))}
            </div>

            {/* Contenu onglet */}
            {tab === "visiteurs"
              ? <VisiteursTab lang={lang} agent={agent} />
              : <PatrolTab lang={lang} agent={agent} patrolLines={patrolLines} patrolLine={patrolLine} threats={threats} threatCount={threatCount} timeStr={timeStr} />
            }

          </div>
        </>
      )}
    </>
  );
}
