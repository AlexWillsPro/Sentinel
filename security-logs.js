// Gestion des logs de sécurité avec stockage en base de données (2 jours de rétention)
import { pb } from '../lib/pocketbase.js';

const RETENTION_DAYS = 2;
const LOG_COLLECTION = 'security_logs';

export async function createSecurityLog(event) {
  try {
    // Vérifier que la collection existe, sinon la créer
    const data = {
      timestamp: new Date().toISOString(),
      type: event.type || 'unknown',
      severity: event.severity || 'info',
      ip_address: event.ip || 'unknown',
      agent: event.agent || 'system',
      description: event.description || '',
      details: JSON.stringify(event.details || {}),
      user_id: pb.authStore.record?.id || 'anonymous',
    };

    await pb.collection(LOG_COLLECTION).create(data);
    return true;
  } catch (e) {
    console.error('Error creating security log:', e);
    return false;
  }
}

export async function getSecurityLogs(filters = {}) {
  try {
    const query = [];
    
    // Filtre par date (garder seulement 2 jours)
    const twoAgo = new Date();
    twoAgo.setDate(twoAgo.getDate() - RETENTION_DAYS);
    query.push(`created >= "${twoAgo.toISOString()}"`);
    
    if (filters.severity) query.push(`severity = "${filters.severity}"`);
    if (filters.type) query.push(`type = "${filters.type}"`);
    if (filters.ip) query.push(`ip_address = "${filters.ip}"`);
    
    const logs = await pb.collection(LOG_COLLECTION).getList(1, 500, {
      filter: query.join(' && '),
      sort: '-created',
    });
    
    return logs.items || [];
  } catch (e) {
    console.error('Error fetching security logs:', e);
    return [];
  }
}

export async function getLogsByType(type) {
  return getSecurityLogs({ type });
}

export async function getLogsBySeverity(severity) {
  return getSecurityLogs({ severity });
}

export async function getBlockedIPLogs() {
  return getSecurityLogs({ type: 'ip_blocked' });
}

export async function getThreatCount(severity = null) {
  try {
    const filter = severity ? `severity = "${severity}"` : '';
    const logs = await pb.collection(LOG_COLLECTION).getList(1, 1, {
      filter: filter,
    });
    return logs.totalItems || 0;
  } catch (e) {
    return 0;
  }
}

export async function clearOldLogs() {
  try {
    const twoAgo = new Date();
    twoAgo.setDate(twoAgo.getDate() - RETENTION_DAYS);
    
    // Supprimer les logs plus anciens que 2 jours
    const oldLogs = await pb.collection(LOG_COLLECTION).getList(1, 500, {
      filter: `created < "${twoAgo.toISOString()}"`,
    });
    
    for (const log of oldLogs.items) {
      await pb.collection(LOG_COLLECTION).delete(log.id);
    }
    
    return oldLogs.items.length;
  } catch (e) {
    console.error('Error clearing old logs:', e);
    return 0;
  }
}
