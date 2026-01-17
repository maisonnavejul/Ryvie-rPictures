# Comportement de connexion rPictures

## 🔄 Scénarios de connexion

### 📡 **Scénario 1 : ryvie.local accessible (réseau local)**

#### Au login :

```
1. SmartUrlSelectorService.selectServerUrl()
   ↓
2. Test connexion à http://ryvie.local:3013
   ✅ Succès
   ↓
3. Utilise http://ryvie.local:3013
   ↓
4. En arrière-plan : RyvieApiService récupère les infos tunnel
   - Authentification sur http://ryvie.local:3002/api/authenticate
   - Récupération de ryvieId, tunnelHost, publicUrl
   - Sauvegarde dans Store
```

**Résultat** :

- `serverUrl` = `http://ryvie.local:3013`
- `ryvieId` = `ryvie-abc123...` (sauvegardé)
- `tunnelHost` = `100.64.0.5` (sauvegardé)
- `publicUrl` = `http://100.64.0.5:3013` (sauvegardé)

---

### 🌐 **Scénario 2 : ryvie.local NON accessible (hors réseau local)**

#### Au login :

```
1. SmartUrlSelectorService.selectServerUrl()
   ↓
2. Test connexion à http://ryvie.local:3013
   ❌ Échec (timeout)
   ↓
3. Récupère publicUrl du Store : http://100.64.0.5:3013
   ✅ Utilise l'IP du tunnel
   ↓
4. Connexion via le tunnel Netbird
```

**Résultat** :

- `serverUrl` = `http://100.64.0.5:3013` (IP tunnel)
- Utilise les infos sauvegardées précédemment

**⚠️ Important** :

- L'authentification Ryvie (port 3002) ne peut PAS se faire via le tunnel
- Les infos tunnel (ryvieId, tunnelHost, publicUrl) sont récupérées uniquement en local
- Une fois sauvegardées, elles sont réutilisées même hors réseau local

---

### 🔄 **Scénario 3 : Déconnexion (logout)**

#### Comportement actuel :

```dart
// Dans auth.service.dart - clearLocalData()
await Future.wait([
  _authRepository.clearLocalData(),
  Store.delete(StoreKey.currentUser),
  Store.delete(StoreKey.accessToken),
  Store.delete(StoreKey.assetETag),
  // ...
  Store.delete(StoreKey.ryvieId),        // ❌ SUPPRIMÉ
  Store.delete(StoreKey.tunnelHost),     // ❌ SUPPRIMÉ
  Store.delete(StoreKey.publicUrl),      // ❌ SUPPRIMÉ
]);
```

**Problème** : Les infos tunnel sont supprimées au logout !

**Ce qui se passe** :

1. Utilisateur clique sur "Déconnexion"
2. `clearLocalData()` supprime TOUT, y compris les infos tunnel
3. Retour à l'écran de login
4. Si l'utilisateur n'est PAS sur le réseau local :
   - ❌ Pas de `publicUrl` sauvegardée
   - ❌ Pas de `tunnelHost` sauvegardé
   - ❌ Impossible de se connecter via le tunnel

**Solution attendue** :

```dart
// Logout devrait GARDER les infos tunnel
await Future.wait([
  _authRepository.clearLocalData(),
  Store.delete(StoreKey.currentUser),
  Store.delete(StoreKey.accessToken),
  Store.delete(StoreKey.assetETag),
  // ...
  // NE PAS supprimer :
  // Store.delete(StoreKey.ryvieId),
  // Store.delete(StoreKey.tunnelHost),
  // Store.delete(StoreKey.publicUrl),
]);
```

---

### 🔀 **Scénario 4 : Changement de serveur ("Changer de Ryvie")**

#### Comportement actuel :

```dart
// Dans auth.service.dart - clearAllData()
await Future.wait([
  _authRepository.clearLocalData(),
  Store.delete(StoreKey.currentUser),
  Store.delete(StoreKey.accessToken),
  // ...
  Store.delete(StoreKey.ryvieId),        // ✅ SUPPRIMÉ
  Store.delete(StoreKey.tunnelHost),     // ✅ SUPPRIMÉ
  Store.delete(StoreKey.publicUrl),      // ✅ SUPPRIMÉ
  Store.delete(StoreKey.serverUrl),      // ✅ SUPPRIMÉ
]);
```

**Comportement correct** : Tout est supprimé, l'utilisateur peut se connecter à un nouveau Ryvie.

---

## 🔍 **Vérification du RyvieId (ServerHealthCheck)**

### Quand ryvie.local est accessible :

```
1. App démarre
   ↓
2. ServerHealthCheck.performHealthCheck()
   ↓
3. Détecte que serverUrl contient "ryvie.local"
   ↓
4. Appelle _checkLocalConnectionWithRyvieId()
   ↓
5. Récupère le ryvieId actuel du serveur local
   ↓
6. Compare avec le ryvieId sauvegardé

   SI DIFFÉRENT :
   ↓
   7. Bascule automatiquement vers le tunnel
      authProvider.setOpenApiServiceEndpoint(forceTunnel: true)
   ↓
   8. Utilise publicUrl au lieu de ryvie.local
```

**Exemple** :

- RyvieId sauvegardé : `ryvie-abc123`
- RyvieId du serveur local : `ryvie-xyz789`
- ⚠️ Pas le même Ryvie !
- ✅ Bascule automatiquement vers le tunnel

---

## 📊 **Tableau récapitulatif**

| Scénario                      | ryvie.local     | Infos tunnel sauvegardées           | Résultat                     |
| ----------------------------- | --------------- | ----------------------------------- | ---------------------------- |
| **Login local**               | ✅ Accessible   | ✅ Récupérées et sauvegardées       | Utilise ryvie.local          |
| **Login distant**             | ❌ Inaccessible | ✅ Déjà sauvegardées                | Utilise publicUrl (tunnel)   |
| **Login distant (1ère fois)** | ❌ Inaccessible | ❌ Pas encore sauvegardées          | ❌ Échec connexion           |
| **Logout**                    | N/A             | ❌ **SUPPRIMÉES** (problème actuel) | Problème si pas en local     |
| **Changer de Ryvie**          | N/A             | ❌ SUPPRIMÉES (normal)              | Permet de changer de serveur |
| **RyvieId différent**         | ✅ Accessible   | ✅ Sauvegardées                     | Bascule auto vers tunnel     |

---

## 🐛 **Problème identifié**

### Le problème actuel :

**Lors du logout, les infos tunnel sont supprimées.**

Cela pose problème si :

1. L'utilisateur se connecte en local (récupère les infos tunnel)
2. L'utilisateur se déconnecte
3. L'utilisateur n'est plus sur le réseau local
4. ❌ Impossible de se reconnecter (pas d'infos tunnel)

### La solution :

**Modifier `clearLocalData()` pour NE PAS supprimer les infos tunnel :**

```dart
Future<void> clearLocalData() async {
  await _backgroundSyncManager.cancel();
  await Future.wait([
    _authRepository.clearLocalData(),
    Store.delete(StoreKey.currentUser),
    Store.delete(StoreKey.accessToken),
    Store.delete(StoreKey.assetETag),
    Store.delete(StoreKey.autoEndpointSwitching),
    Store.delete(StoreKey.preferredWifiName),
    Store.delete(StoreKey.localEndpoint),
    Store.delete(StoreKey.externalEndpointList),
    // ✅ GARDER les infos tunnel au logout :
    // Store.delete(StoreKey.ryvieId),
    // Store.delete(StoreKey.tunnelHost),
    // Store.delete(StoreKey.publicUrl),
  ]);
}
```

**Garder `clearAllData()` tel quel pour "Changer de Ryvie" :**

```dart
Future<void> clearAllData() async {
  await _backgroundSyncManager.cancel();
  await Future.wait([
    _authRepository.clearLocalData(),
    Store.delete(StoreKey.currentUser),
    Store.delete(StoreKey.accessToken),
    Store.delete(StoreKey.assetETag),
    Store.delete(StoreKey.autoEndpointSwitching),
    Store.delete(StoreKey.preferredWifiName),
    Store.delete(StoreKey.localEndpoint),
    Store.delete(StoreKey.externalEndpointList),
    Store.delete(StoreKey.serverUrl),
    // ✅ SUPPRIMER les infos tunnel pour changer de serveur :
    Store.delete(StoreKey.ryvieId),
    Store.delete(StoreKey.tunnelHost),
    Store.delete(StoreKey.publicUrl),
  ]);
}
```

---

## 🎯 **Résumé**

### Ce qui fonctionne actuellement :

✅ Connexion locale (ryvie.local)
✅ Récupération des infos tunnel en local
✅ Basculement auto vers tunnel si RyvieId différent
✅ "Changer de Ryvie" supprime tout

### Ce qui ne fonctionne PAS actuellement :

❌ Logout supprime les infos tunnel
❌ Impossible de se reconnecter hors réseau local après un logout

### Ce qui devrait être corrigé :

🔧 Modifier `clearLocalData()` pour garder les infos tunnel
🔧 Seul `clearAllData()` devrait supprimer les infos tunnel

---

## 📝 **Note importante**

**L'authentification Ryvie (port 3002) n'est accessible QUE en local.**

Cela signifie que :

- Les infos tunnel peuvent être récupérées UNIQUEMENT quand ryvie.local est accessible
- Une fois récupérées, elles doivent être CONSERVÉES pour permettre la connexion via le tunnel
- Le logout ne devrait PAS les supprimer
- Seul "Changer de Ryvie" devrait les supprimer
