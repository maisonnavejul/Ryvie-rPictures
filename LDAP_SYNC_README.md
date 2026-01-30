# Synchronisation LDAP pour rPictures

## 📋 Vue d'ensemble

La synchronisation LDAP permet de maintenir automatiquement les utilisateurs de rPictures en phase avec votre serveur LDAP (Ryvie Manager). Cette synchronisation est **unidirectionnelle** : LDAP → rPictures.

### Fonctionnalités

- ✅ **Création automatique** des nouveaux utilisateurs LDAP dans rPictures
- ✅ **Mise à jour** des informations utilisateur (email, nom, statut admin)
- ✅ **Suppression automatique** des utilisateurs retirés de LDAP
- ✅ **Préservation des données** lors du changement d'email (grâce au tracking par UID)
- ✅ **Logs minimalistes** et résumé clair des opérations

## Configuration

Les variables d'environnement suivantes doivent être configurées pour utiliser la synchronisation LDAP :

### Variables obligatoires

- `LDAP_URL` : URL du serveur LDAP (par défaut: `ldap://openldap:1389`)
- `LDAP_BIND_DN` : DN de connexion pour le bind LDAP (par défaut: `cn=admin,dc=example,dc=org`)
- `LDAP_BIND_PASSWORD` : Mot de passe pour le bind LDAP (par défaut: `adminpassword`)
- `LDAP_USER_BASE_DN` : Base DN pour la recherche des utilisateurs (par défaut: `ou=users,dc=example,dc=org`)

### Variables optionnelles

- `LDAP_USER_FILTER` : Filtre LDAP pour les utilisateurs (par défaut: `(objectClass=inetOrgPerson)`)
- `LDAP_UID_ATTRIBUTE` : Attribut LDAP pour l'identifiant unique (par défaut: `uid`)
- `LDAP_EMAIL_ATTRIBUTE` : Attribut LDAP pour l'email (par défaut: `mail`)
- `LDAP_NAME_ATTRIBUTE` : Attribut LDAP pour le nom (par défaut: `cn`)
- `LDAP_GIVEN_NAME_ATTRIBUTE` : Attribut LDAP pour le prénom (par défaut: `givenName`)
- `LDAP_SN_ATTRIBUTE` : Attribut LDAP pour le nom de famille (par défaut: `sn`)
- `LDAP_PASSWORD_ATTRIBUTE` : Attribut LDAP pour le mot de passe (par défaut: `userPassword`)
- `LDAP_ADMIN_GROUP` : Nom du groupe LDAP pour les administrateurs (par défaut: `admins`)

## Exemple de configuration dans docker-compose.yml

```yaml
services:
  immich-server:
    environment:
      - LDAP_URL=ldap://openldap:1389
      - LDAP_BIND_DN=cn=admin,dc=example,dc=org
      - LDAP_BIND_PASSWORD=adminpassword
      - LDAP_USER_BASE_DN=ou=users,dc=example,dc=org
      - LDAP_USER_FILTER=(objectClass=inetOrgPerson)
      - LDAP_UID_ATTRIBUTE=uid
      - LDAP_EMAIL_ATTRIBUTE=mail
      - LDAP_NAME_ATTRIBUTE=cn
      - LDAP_GIVEN_NAME_ATTRIBUTE=givenName
      - LDAP_SN_ATTRIBUTE=sn
      - LDAP_PASSWORD_ATTRIBUTE=userPassword
      - LDAP_ADMIN_GROUP=admins
```

## Utilisation

### Endpoint API

La synchronisation peut être déclenchée via l'endpoint suivant :

```
GET /ldap/sync
```

Cet endpoint est **public** et ne nécessite pas d'authentification. Pour des raisons de sécurité, vous devriez le protéger au niveau du reverse proxy ou ajouter une authentification si nécessaire.

### Exemple avec curl

```bash
curl -X GET http://localhost:2283/api/ldap/sync
```

### Réponse

L'endpoint retourne un objet JSON avec les statistiques de synchronisation :

```json
{
  "created": 5,
  "updated": 2,
  "deleted": 1,
  "errors": 0
}
```

- `created` : Nombre d'utilisateurs créés
- `updated` : Nombre d'utilisateurs mis à jour
- `deleted` : Nombre d'utilisateurs supprimés (absents de LDAP)
- `errors` : Nombre d'erreurs rencontrées

## 🚀 Fonctionnement détaillé

### Identifiant unique

Le script utilise le champ **`uid`** LDAP comme identifiant unique et immuable :
- Stocké dans `storageLabel` dans rPictures
- Permet de suivre un utilisateur même si son email change
- **Ne jamais modifier le `uid` d'un utilisateur existant**

### 1. Création d'utilisateur

Quand un nouvel utilisateur est détecté dans LDAP :

1. **Création du compte rPictures**
   - `storageLabel` = `uid` LDAP (identifiant unique)
   - `email` = email LDAP
   - `name` = `givenName sn` ou `uid` si absent
   - `isAdmin` = basé sur l'appartenance au groupe admin

**Log affiché :**
```
🆕 Creating: uid (email@example.com)
```

### 2. Mise à jour d'utilisateur

Le script détecte et met à jour automatiquement :

#### Email modifié
```
📧 Email updated: uid (old@email.com → new@email.com)
```
**Important :** Les données utilisateur (photos, albums) sont **préservées** car l'identification se fait par `uid`, pas par email.

#### Nom/Prénom modifié
Mise à jour silencieuse (pas de log sauf erreur).

#### Statut admin modifié
Mise à jour silencieuse basée sur l'appartenance au groupe LDAP.

### 3. Suppression d'utilisateur

Quand un utilisateur n'existe plus dans LDAP :

1. **Détection** : Le `uid` n'est plus présent dans LDAP
2. **Suppression douce** : 
   - `deletedAt` → date actuelle
   - L'utilisateur est marqué comme supprimé mais les données sont préservées

**Log affiché :**
```
🗑️  Deleting: uid (email@example.com)
```

## 📈 Résumé de synchronisation

À la fin de chaque exécution, le script affiche un résumé compact :

```
📊 Sync Summary: 🆕 2 created | 🔄 3 updated | 🗑️ 1 deleted | ❌ 0 errors
```

- **🆕 Created** : Nouveaux utilisateurs ajoutés
- **🔄 Updated** : Utilisateurs mis à jour (email, nom, etc.)
- **🗑️ Deleted** : Utilisateurs supprimés (absents de LDAP)
- **❌ Errors** : Erreurs rencontrées

## 📝 Logs détaillés

Le module génère des logs avec emojis pour faciliter la lecture :

- 🔄 Démarrage de la synchronisation
- ✅ Connexion LDAP établie
- 📋 Nombre d'utilisateurs trouvés
- 🆕 Création d'utilisateur
- 📧 Changement d'email
- 🗑️ Suppression d'utilisateur
- ⚠️ Avertissements (utilisateur sans mot de passe)
- ❌ Erreurs
- 📊 Résumé final

## ⚠️ Limitations et précautions

### Limitations actuelles

1. **Synchronisation unidirectionnelle** : LDAP → rPictures uniquement
   - Les modifications dans rPictures ne sont PAS synchronisées vers LDAP
   - Gérer les utilisateurs via Ryvie Manager (interface LDAP)

2. **Suppression douce uniquement**
   - Les utilisateurs sont marqués comme supprimés (`deletedAt`)
   - Les données (photos, albums) sont préservées
   - Pas de suppression définitive automatique

### Précautions importantes

⚠️ **Ne jamais modifier le `uid` LDAP** d'un utilisateur existant
- Le script le considérera comme un nouvel utilisateur
- L'ancien compte sera marqué comme supprimé

⚠️ **Sauvegardes régulières**
- Avant toute synchronisation massive
- Avant modification de la structure LDAP

⚠️ **Tester en environnement de développement**
- Valider les modifications du script avant production
- Vérifier les logs après chaque synchronisation

## 🔐 Sécurité

### Bonnes pratiques

1. **Mot de passe LDAP sécurisé**
   - Utiliser Docker secrets ou variables d'environnement sécurisées
   - Ne jamais commiter les credentials dans le code

2. **Connexion LDAP chiffrée** (recommandé)
   ```yaml
   LDAP_URL: "ldaps://openldap:636"
   ```

3. **Permissions restreintes**
   - Le compte LDAP de synchronisation doit avoir accès en lecture seule
   - Pas besoin de droits d'écriture sur LDAP

4. **Protection de l'endpoint**
   - L'endpoint `/api/ldap/sync` est public par défaut
   - Protégez-le au niveau du reverse proxy ou ajoutez une authentification

5. **Hashage des mots de passe**
   - Les mots de passe LDAP sont hashés avec bcrypt (10 rounds)
   - Les mots de passe ne sont jamais loggés

## 🛠️ Automatisation

### Cron job

Ajoutez dans votre `crontab` :

```bash
# Synchronisation toutes les heures
0 * * * * curl -X GET http://localhost:2283/api/ldap/sync >> /var/log/rpictures-ldap-sync.log 2>&1
```

### Systemd timer

```ini
# /etc/systemd/system/rpictures-ldap-sync.timer
[Unit]
Description=rPictures LDAP Sync Timer

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/rpictures-ldap-sync.service
[Unit]
Description=rPictures LDAP Synchronization

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -X GET http://localhost:2283/api/ldap/sync
```

Activation :
```bash
sudo systemctl enable rpictures-ldap-sync.timer
sudo systemctl start rpictures-ldap-sync.timer
```

## 📚 Dépendances

- `ldapjs` : Client LDAP pour Node.js
- `@types/ldapjs` : Types TypeScript pour ldapjs

Ces dépendances ont été installées automatiquement lors de la création du module.

---

*Dernière mise à jour : 29 janvier 2026*
*Inspiré de l'implémentation rDrive*
