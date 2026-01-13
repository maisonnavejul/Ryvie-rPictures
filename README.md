<p align="center"> 
  <br/>
  <a href="https://opensource.org/license/agpl-v3"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg?color=3F51B5&style=for-the-badge&label=License&logoColor=000000&labelColor=ececec" alt="License: AGPLv3"></a>
  <br/>
  <br/>
</p>

<p align="center">
  <img src="./web/static/rpictures-logo.png" width="300" alt="Logo rPictures">
</p>

<h1 align="center">rPictures</h1>
<h3 align="center">Galerie photo et vidéo auto‑hébergée pour votre cloud personnel</h3>

<br/>

---

## Présentation

**rPictures** est une application de sauvegarde, d'organisation et de consultation de photos/vidéos, pensée pour être **auto‑hébergée** sur votre propre serveur (chez vous ou sur un VPS), avec une expérience moderne proche de Google Photos, mais en gardant **le contrôle total sur vos données**.

rPictures est développé spécifiquement pour **RyvieOS**, le système d'exploitation de cloud personnel à la maison. Il s'intègre nativement dans cet écosystème pour fournir une brique « Photos/Vidéos » cohérente avec le reste des services (fichiers, notes, etc.).

rPictures est un **fork** du projet open source [Immich](https://github.com/immich-app/immich). Il reprend ses fondations techniques et fonctionnelles, tout en étant adapté et optimisé pour l'environnement RyvieOS.

---

## Pourquoi rPictures ?

- **Auto‑hébergé à la maison**  
  Déployez rPictures sur votre propre serveur (NUC, mini‑PC, NAS, VPS…) et gardez vos souvenirs près de vous.

- **Contrôle et confidentialité des données**  
  Pas de solution SaaS opaque : vos photos et vidéos restent sous votre contrôle, chiffrées et stockées là où vous le décidez.

- **Expérience moderne**  
  Interface moderne, recherche avancée, albums partagés, sauvegarde automatique depuis le mobile : une expérience proche des grandes plateformes, mais sans les inconvénients.

- **Conçu pour RyvieOS**  
  Développé nativement pour **RyvieOS**, le système d'exploitation de cloud personnel : authentification LDAP intégrée, supervision, sauvegardes automatiques et gestion centralisée des services.

- **Basé sur un projet mature**  
  Repose sur une base technique robuste issue du projet original Immich, bénéficiant de son expérience et de sa communauté.

---

## Liens

- **Code source** : https://github.com/ryvieos/Ryvie-rPictures  
- **Site RyvieOS** : https://ryvie.fr  
- **Documentation** : à venir (se référer au dépôt GitHub)  
- **Suivi des issues / demandes de fonctionnalités** : https://github.com/ryvieos/Ryvie-rPictures/issues  
- **Roadmap** : à venir  
- **Démo** : voir la section ci‑dessous

---

## Démo

Une démo publique sera **bientôt disponible**.

En attendant, vous pouvez tester rPictures en local ou sur votre propre serveur en suivant la section **Installation** et **Déploiement avec Docker Compose** ci‑dessous.

---

## Fonctionnalités

La liste ci‑dessous reprend les principales fonctionnalités disponibles dans rPictures, côté **mobile** et **web** :

| Fonctionnalité                                      | Mobile | Web |
| :-------------------------------------------------- | :----: | :--: |
| Upload et visualisation de photos et vidéos         |  Oui   | Oui |
| Sauvegarde automatique à l’ouverture de l’app      |  Oui   | N/A |
| Prévention de la duplication des médias            |  Oui   | Oui |
| Sélection d’albums pour la sauvegarde              |  Oui   | N/A |
| Téléchargement vers l’appareil local               |  Oui   | Oui |
| Support multi‑utilisateurs                          |  Oui   | Oui |
| Albums et albums partagés                          |  Oui   | Oui |
| Barre de défilement rapide / scrubbable            |  Oui   | Oui |
| Support de formats RAW                             |  Oui   | Oui |
| Vue métadonnées (EXIF, carte, etc.)               |  Oui   | Oui |
| Recherche par métadonnées, objets, visages, CLIP   |  Oui   | Oui |
| Fonctions d’administration (gestion des comptes)   |  Non   | Oui |
| Sauvegarde en arrière‑plan                         |  Oui   | N/A |
| Virtual scroll (grandes galeries fluides)          |  Oui   | Oui |
| Support OAuth                                      |  Oui   | Oui |
| Clés API                                           |  N/A   | Oui |
| Sauvegarde/lecture LivePhoto / MotionPhoto         |  Oui   | Oui |
| Support des images 360°                            |  Non   | Oui |
| Structure de stockage définie par l’utilisateur    |  Oui   | Oui |
| Partage public                                     |  Oui   | Oui |
| Archivage et favoris                               |  Oui   | Oui |
| Carte globale                                      |  Oui   | Oui |
| Partage partenaire                                 |  Oui   | Oui |
| Reconnaissance faciale et regroupement             |  Oui   | Oui |
| Souvenirs (x années en arrière)                    |  Oui   | Oui |
| Support hors‑ligne                                 |  Oui   | Non |
| Galerie en lecture seule                           |  Oui   | Oui |
| Photos empilées                                    |  Oui   | Oui |
| Tags / étiquettes                                  |  Non   | Oui |
| Vue par dossiers                                   |  Oui   | Oui |

> Remarque : certaines fonctionnalités peuvent nécessiter des services supplémentaires (moteur de recherche, service de machine learning, etc.), généralement fournis via Docker.

---

## Stack technique (vue d’ensemble)

rPictures est composé de plusieurs services, typiquement déployés via **Docker Compose** :

- **Services applicatifs**  
  Services backend et web pour gérer les comptes utilisateurs, les albums, l’API, la synchronisation, etc.

- **Base de données**  
  Base de données relationnelle (par exemple PostgreSQL) pour les métadonnées et la gestion des utilisateurs.

- **Cache / file de messages**  
  Service de cache / file (par exemple Redis) pour la gestion des jobs, des sessions et de certaines opérations asynchrones.

- **Moteur de recherche & ML**  
  Services annexes pour la recherche par texte / similarité, la détection de visages, d’objets, etc.

- **Applications clientes**  
  - Application web rPictures  
  - Applications mobiles (Android / iOS) basées sur le client compatible avec le backend rPictures

Les détails précis de la stack et des services déployés sont décrits dans les fichiers de configuration Docker du dépôt (dossier `docker/`).

---

## Installation

### Prérequis

- Un serveur Linux (ou machine locale) avec :
  - Docker et le plugin Docker Compose
  - Une connexion réseau stable
  - Un espace disque suffisant pour stocker vos photos/vidéos
- Un nom de domaine (optionnel mais recommandé) si vous exposez rPictures sur Internet
- **RyvieOS** (recommandé) pour une intégration complète avec l'authentification LDAP, la supervision et les sauvegardes automatiques

### Récupérer le code

```bash
git clone https://github.com/ryvieos/Ryvie-rPictures.git
cd Ryvie-rPictures
```

### Déploiement rapide avec Docker Compose

Un exemple standard consiste à utiliser les fichiers fournis dans le dossier `docker/` :

```bash
# Depuis la racine du dépôt
docker compose -f docker/docker-compose.yml up -d
```

Cette commande :

- Télécharge les images nécessaires
- Démarre les services rPictures (API, web, services techniques…)
- Crée les volumes nécessaires pour les données et les métadonnées

> Pensez à vérifier et adapter le fichier `docker-compose.yml` (ports exposés, chemins de volumes, etc.) avant un déploiement en production.

### Première connexion

1. Une fois les conteneurs démarrés, accédez à l’interface web :  
   `http://votre‑serveur:PORT` (PORT selon votre configuration Docker, par exemple `2283` ou autre valeur définie).
2. Créez un compte administrateur si nécessaire (ou utilisez l’utilisateur initial configuré par l’application).
3. Configurez :
   - Vos dossiers de sauvegarde
   - La langue de l’interface
   - Les paramètres de reconnaissance (si activés)

---

## Configuration

La configuration de rPictures se fait principalement via :

- **Variables d’environnement**  
  Pour les accès à la base de données, au cache, aux services de recherche, aux chemins de stockage, etc.  
  Ces variables sont généralement définies dans :
  - Les fichiers `docker-compose.yml`
  - Un éventuel fichier `.env` chargé par Docker

- **Volumes Docker**  
  Pour les répertoires de stockage des originaux, des miniatures, des fichiers dérivés, etc.

Points d’attention :

- **Stockage** :  
  - Définissez un volume pour les photos/vidéos, par exemple monté vers `/photos` dans le conteneur.  
  - Assurez‑vous que ce volume est sauvegardé par vos routines de backup (NAS, disque externe, etc.).

- **Sauvegardes** :  
  - Respectez autant que possible la règle **3‑2‑1** (3 copies, 2 supports différents, 1 hors‑site) pour vos photos/vidéos.  
  - rPictures ne remplace pas une stratégie de sauvegarde complète.

- **Sécurité & accès** :  
  - Placez rPictures derrière un reverse proxy (par exemple Traefik, Caddy, Nginx) pour gérer TLS/HTTPS.  
  - Restreignez l’accès administratif aux utilisateurs de confiance.

---

## Contribution

Les contributions à rPictures sont les bienvenues !

- **Signaler un bug** : ouvrez une issue avec :
  - La version de rPictures
  - Votre configuration (Docker, OS, etc.)
  - Les étapes pour reproduire le problème
- **Proposer une nouvelle fonctionnalité** : créez une issue de type *feature request* en expliquant le besoin, le contexte (notamment avec RyvieOS) et un exemple d'usage.
- **Envoyer une Pull Request** :
  - Forkez le dépôt : https://github.com/ryvieos/Ryvie-rPictures
  - Créez une branche dédiée
  - Ajoutez vos modifications avec des tests si possible
  - Ouvrez une PR en décrivant clairement votre changement

Avant de contribuer, consultez les éventuelles directives dans `CONTRIBUTING.md` ou la documentation du dépôt si elles existent.

---

## Projet original

rPictures est basé sur le projet open source **Immich** :

- **Projet original** : Immich – Self‑hosted photo and video management solution  
- **Dépôt original** : https://github.com/immich-app/immich  

Un grand merci à toute l’équipe et à la communauté Immich pour leur travail exceptionnel, qui sert de base solide à rPictures.

---

## Licence

rPictures est distribué sous licence **AGPLv3** (Affero General Public License version 3), conformément au projet original.

Pour plus de détails, consultez le fichier `LICENSE` à la racine du dépôt ou la page :  
https://opensource.org/license/agpl-v3

---

## Auteurs & contributeurs

<a href="https://github.com/ryvieos/Ryvie-rPictures/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ryvieos/Ryvie-rPictures" width="100%" alt="Contributeurs de rPictures"/>
</a>

Merci à toutes les personnes qui participent à faire évoluer rPictures et à construire un cloud personnel respectueux de la vie privée avec RyvieOS.
