# Sentinel

<p align="center"><img src="sentinel-logo.svg" alt="Sentinel — Open Security" width="900" /></p>

<p align="center"><strong>Open security, community built.</strong><br/>A cyberpunk-inspired security panel for React applications.</p>

Sentinel combine une patrouille visuelle en temps réel, des compteurs de menaces et une vue des visiteurs réservée aux administrateurs.

## Introduction

Sentinel donne une présence claire et compréhensible à la sécurité d’une application : trois agents — GHOST, VIPER et CIPHER — se relaient pour afficher l’état de la surveillance. Le composant reste volontairement modulaire afin que la communauté puisse l’adapter, l’améliorer et l’intégrer à ses propres outils.

## Fonctionnalités

- Agents de sécurité avec rotations horaires.
- Indicateurs de menaces fournis par l’application hôte.
- Télémétrie visiteur chiffrée avec AES-GCM.
- Vue PocketBase des visiteurs réservée aux utilisateurs autorisés.
- Composant React extensible par la communauté.

## Configuration et sécurité

Aucune clé de chiffrement n’est présente dans ce dépôt. À l’exécution, fournissez `globalThis.SENTINEL_AES_KEY_HEX` avec une clé aléatoire de 32 octets encodée sur 64 caractères hexadécimaux. Générez-la avec `openssl rand -hex 32` et injectez-la via les secrets de votre environnement. Ne la commitez jamais dans Git.

L’application hôte doit imposer l’authentification et l’autorisation avant d’exposer les visiteurs. Avant de collecter une adresse IP, une localisation approximative, des caractéristiques d’appareil ou des données de navigation, informez clairement les personnes, recueillez le consentement requis, limitez la conservation et prévoyez les procédures d’accès et de suppression conformément au RGPD et aux règles locales.

## RGPD et protection des données

Sentinel applique désormais la protection de la vie privée par défaut : `trackVisitor()` ne collecte rien tant qu’un consentement explicite n’a pas été enregistré. Utilisez `setTrackingConsent(true)` après l’action positive de votre bandeau de consentement, et `setTrackingConsent(false)` pour retirer ce choix. Le bouton de refus doit être aussi visible et simple que le bouton d’acceptation.

Cette mesure technique ne remplace pas vos obligations. Avant la mise en production, l’intégrateur doit :

- définir la finalité, la base légale, la durée de conservation et les destinataires ;
- informer les visiteurs des données collectées : IP, localisation approximative, appareil, navigateur, navigation et référent ;
- documenter les appels à `api.ipify.org` et `ipapi.co`, leurs sous-traitants et les transferts éventuels hors UE ;
- afficher une politique de confidentialité et recueillir le consentement requis avant tout appel ;
- permettre le retrait du consentement, l’accès, la rectification, l’effacement et la limitation ;
- sécuriser PocketBase avec authentification, rôles, règles d’accès, chiffrement côté serveur et journaux d’audit ;
- limiter les champs et la durée de conservation, puis supprimer ou anonymiser automatiquement les anciennes données ;
- protéger la clé AES dans un backend ou un gestionnaire de secrets. Une variable injectée dans le navigateur reste techniquement visible par le visiteur ;
- vérifier si une analyse d’impact (AIPD/DPIA), un registre des traitements ou un accord de sous-traitance est nécessaire.

Ne déployez pas le suivi public avant validation de ces points par le responsable du traitement ou votre conseil juridique. Le dépôt fournit des garde-fous techniques, pas une certification automatique de conformité.

## Intégration

Importez les composants dans votre application React, adaptez l’import PocketBase et fournissez les modules référencés par `Sentinel.jsx` (`security.js` et `api/api-key-manager.js`). Le module de suivi attend une collection PocketBase nommée `visiteurs_sentinel`.

## Communauté

Les contributions sont les bienvenues. Forkez le projet, ouvrez une issue ou proposez une pull request. Décrivez clairement vos changements et ne publiez jamais de secrets, de données personnelles ou d’exports de production.

## Licence

Sentinel est distribué sous licence GNU GPL v3.0. Consultez le fichier `LICENSE`.
