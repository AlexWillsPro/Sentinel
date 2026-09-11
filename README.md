# Sentinel

Sentinel est un panneau de sécurité open source, inspiré de l’esthétique cyberpunk, pour les applications React. Il combine une patrouille visuelle en temps réel, des compteurs de menaces et une vue des visiteurs réservée aux administrateurs.

## Introduction

Sentinel donne une présence claire et compréhensible à la sécurité d’une application : trois agents — GHOST, VIPER et CIPHER — se relaient pour afficher l’état de la surveillance. Le composant reste volontairement modulaire afin que la communauté puisse l’adapter, l’améliorer et l’intégrer à ses propres outils.

## Fonctionnalités

- Agents de sécurité avec rotations horaires.
- Indicateurs de menaces fournis par l’application hôte.
- Télémétrie visiteur chiffrée avec AES-GCM.
- Vue PocketBase des visiteurs réservée aux utilisateurs autorisés.
- Composant React librement extensible par la communauté.

## Configuration et sécurité

Aucune clé de chiffrement n’est présente dans ce dépôt. À l’exécution, fournissez `globalThis.SENTINEL_AES_KEY_HEX` avec une clé aléatoire de 32 octets encodée sur 64 caractères hexadécimaux. Générez-la avec `openssl rand -hex 32` et injectez-la via les secrets de votre environnement. Ne la commitez jamais dans Git.

L’application hôte doit imposer l’authentification et l’autorisation avant d’exposer les visiteurs. Avant de collecter une adresse IP, une localisation approximative, des caractéristiques d’appareil ou des données de navigation, informez clairement les personnes, recueillez le consentement requis, limitez la conservation et prévoyez les procédures d’accès et de suppression conformément au RGPD et aux règles locales.

## Intégration

Importez les composants dans votre application React, adaptez l’import PocketBase et fournissez les modules référencés par `Sentinel.jsx` (`security.js` et `api/api-key-manager.js`). Le module de suivi attend une collection PocketBase nommée `visiteurs_sentinel`.

## Communauté

Les contributions sont les bienvenues. Forkez le projet, ouvrez une issue ou proposez une pull request. Décrivez clairement vos changements et ne publiez jamais de secrets, de données personnelles ou d’exports de production.

## Licence

Sentinel est distribué sous licence GNU GPL v3.0. Consultez le fichier `LICENSE`.
