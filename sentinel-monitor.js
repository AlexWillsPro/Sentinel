// Sentinel — Surveillance en temps réel du trafic et des clés API
// Stub functions — api-key-manager removed (agents removed 2026-09-15)
const getAuditLog = () => [];
const detectAnomalies = () => [];
import { createSecurityLog } from './security-logs.js';

const THREAT_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

const MONITORED_EVENTS = [
  'api_key_decryption_failed',
  'excessive_key_access',
  'suspicious_user_agent',
  'unusual_access_pattern',
  'encryption_anomaly',
];

class SentinelMonitor {
  constructor() {
    this.threats = [];
    this.blockedIPs = new Set();
    this.ipAccessCount = new Map();
    this.startMonitoring();
  }
  
  startMonitoring() {
    // Vérifier les anomalies toutes les 10 secondes
    setInterval(() => {
      const anomalies = detectAnomalies();
      anomalies.forEach(anomaly => {
        this.logThreat({
          type: anomaly.type,
          severity: anomaly.severity === 'critical' ? THREAT_LEVELS.CRITICAL : THREAT_LEVELS.HIGH,
          details: anomaly,
          timestamp: new Date().toISOString(),
        });
      });
    }, 10000);
  }
  
  logThreat(threat) {
    this.threats.push(threat);
    
    // Garder seulement les 50 dernières menaces en mémoire
    if (this.threats.length > 50) {
      this.threats.shift();
    }
    
    // Sauvegarder en base de données pour rétention 2 jours
    createSecurityLog({
      type: threat.type,
      severity: threat.severity,
      ip: threat.ip || 'unknown',
      description: threat.reason || threat.details?.description || '',
      details: threat,
    });
    
    // Alerter si critique
    if (threat.severity === THREAT_LEVELS.CRITICAL) {
      console.error('🛡️ SENTINEL ALERT — CRITICAL THREAT:', threat);
      this.notifyAdmin(threat);
    }
  }
  
  notifyAdmin(threat) {
    // En production, envoyer un webhook ou une notification
    if (window.__adminNotify) {
      window.__adminNotify({
        source: 'Sentinel',
        threat: threat,
        auditLog: getAuditLog(),
      });
    }
  }
  
  checkAPIKeyAccess(agentName, action) {
    // Vérifier les patterns suspects d'accès aux clés
    const recentAccess = getAuditLog().filter(log => 
      log.agent === agentName && 
      new Date() - new Date(log.timestamp) < 60000
    );
    
    if (recentAccess.length > 5) {
      this.logThreat({
        type: 'suspicious_agent_access',
        severity: THREAT_LEVELS.HIGH,
        agent: agentName,
        accessCount: recentAccess.length,
        timestamp: new Date().toISOString(),
      });
    }
  }
  
  // Bloquer une adresse IP
  blockIP(ipAddress, reason = 'Suspicious activity') {
    this.blockedIPs.add(ipAddress);
    this.logThreat({
      type: 'ip_blocked',
      severity: THREAT_LEVELS.CRITICAL,
      ip: ipAddress,
      reason: reason,
      timestamp: new Date().toISOString(),
    });
    console.error(`🛡️ SENTINEL — IP BLOCKED: ${ipAddress} (${reason})`);
    return true;
  }

  // Vérifier si une IP est bloquée
  isIPBlocked(ipAddress) {
    return this.blockedIPs.has(ipAddress);
  }

  // Débloquer une IP
  unblockIP(ipAddress) {
    this.blockedIPs.delete(ipAddress);
    return true;
  }

  // Tracker les tentatives par IP et bloquer automatiquement après N tentatives suspectes
  trackIPAttempt(ipAddress, isSuccessful = true) {
    const key = ipAddress;
    const current = this.ipAccessCount.get(key) || 0;
    
    if (!isSuccessful) {
      this.ipAccessCount.set(key, current + 1);
      
      // Auto-bloquer après 10 tentatives échouées
      if (current + 1 >= 10) {
        this.blockIP(ipAddress, 'Auto-blocked: 10+ failed attempts');
        return { blocked: true, reason: 'Exceeded max failed attempts' };
      }
    } else {
      // Réinitialiser le compteur sur succès
      this.ipAccessCount.set(key, 0);
    }
    
    return { blocked: false };
  }

  getSecurityStatus() {
    const recentThreats = this.threats.filter(t => 
      new Date() - new Date(t.timestamp) < 3600000 // 1 heure
    );
    
    const criticalCount = recentThreats.filter(t => t.severity === THREAT_LEVELS.CRITICAL).length;
    const highCount = recentThreats.filter(t => t.severity === THREAT_LEVELS.HIGH).length;
    
    return {
      status: criticalCount > 0 ? 'UNDER_ATTACK' : highCount > 3 ? 'ALERT' : 'SECURE',
      criticalThreats: criticalCount,
      highThreats: highCount,
      blockedIPs: Array.from(this.blockedIPs),
      recentThreats: recentThreats.slice(-10),
    };
  }
}

export const sentinelMonitor = new SentinelMonitor();

// Exposer globalement pour Sentinel
window.__sentinelMonitor = (event) => sentinelMonitor.logThreat(event);
window.__sentinelStatus = () => sentinelMonitor.getSecurityStatus();
