# Sentinel Security Monitoring System v1.0

## Contenu du ZIP

**3 modules de sécurité :**

1. **sentinel-monitor.js** — Surveillance en temps réel
   - Détection des menaces automatique
   - Blocage d'IP après 10 tentatives échouées
   - Logs de sécurité avec niveaux de gravité
   
2. **security-logs.js** — Persistance des logs
   - Stockage des événements de sécurité
   - Rétention 2 jours
   - Intégration PocketBase

3. **sentinel-tracking.js** — Suivi du consentement
   - Gestion des consentements utilisateur
   - Tracking opt-in/opt-out
   - Compliance RGPD

## Installation rapide

```bash
# 1. Copier les 3 fichiers dans src/
# 2. Importer dans votre app :

import sentinelMonitor from './api/sentinel-monitor';
import { createSecurityLog } from './api/security-logs';
import { trackingConsent } from './tracking/sentinel-tracking';

# 3. Initialiser au démarrage
sentinelMonitor.start();
```

## Configuration

Vérifiez que votre PocketBase a :
- Collection `security_logs` (auto-créée)
- Règles d'accès : admin uniquement

## Support

Tous les fichiers sont prêts à pusher en production.
