# Corrections du comportement de connexion/déconnexion

## 📋 Résumé des modifications

J'ai corrigé le comportement de l'application pour qu'elle respecte les règles suivantes :

### ✅ Lors de la connexion

- **Récupère automatiquement** : `ryvieId`, `tunnelHost`, `publicUrl`
- **Essaie d'abord** : `ryvie.local:3013` (connexion locale)
- **Fallback automatique** : Utilise l'IP du tunnel si local échoue
- **Validation RyvieId** : Vérifie que le RyvieId correspond (évite de se connecter au mauvais Ryvie)

### ✅ Lors de la déconnexion (bouton "Se déconnecter")

- **Garde** : `ryvieId`, `tunnelHost`, `publicUrl`
- **Supprime** : Token d'accès, données utilisateur, cache
- **Résultat** : Peut se reconnecter facilement au même Ryvie

### ✅ Lors du changement de serveur (bouton "Changer de Ryvie")

- **Supprime TOUT** : `ryvieId`, `tunnelHost`, `publicUrl`, token, données
- **Résultat** : Repart de zéro comme une première connexion

---

## 🔧 Fichiers modifiés

### 1. `/mobile/lib/services/auth.service.dart`

**Problème** : La méthode `clearLocalData()` supprimait TOUT, y compris les infos du tunnel.

**Solution** :

- `clearLocalData()` : Garde les infos tunnel (pour déconnexion)
- `clearAllData()` : Supprime tout (pour changement de serveur)

```dart
// AVANT (ligne 167-181)
Future<void> clearLocalData() async {
  await Future.wait([
    // ... autres suppressions ...
    Store.delete(StoreKey.ryvieId),      // ❌ Supprimait tout
    Store.delete(StoreKey.tunnelHost),   // ❌ Supprimait tout
    Store.delete(StoreKey.publicUrl),    // ❌ Supprimait tout
  ]);
}

// APRÈS (ligne 167-209)
Future<void> clearLocalData() async {
  await Future.wait([
    // ... autres suppressions ...
    // ⚠️ NE PAS SUPPRIMER: ryvieId, tunnelHost, publicUrl
    // Ces infos sont conservées pour permettre une reconnexion facile
  ]);
}

Future<void> clearAllData() async {
  await Future.wait([
    // ... autres suppressions ...
    Store.delete(StoreKey.ryvieId),      // ✅ Supprime tout
    Store.delete(StoreKey.tunnelHost),   // ✅ Supprime tout
    Store.delete(StoreKey.publicUrl),    // ✅ Supprime tout
  ]);
}
```

---

### 2. `/mobile/lib/providers/auth.provider.dart`

**Ajout** : Méthode `clearAllData()` pour le changement de serveur.

```dart
// AJOUT (ligne 225-228)
/// Efface TOUTES les données pour un changement de Ryvie
Future<void> clearAllData() {
  return _authService.clearAllData();
}
```

---

### 3. `/mobile/lib/widgets/forms/login/login_form.dart`

**Problème** : Le bouton "Changer de Ryvie" appelait `resetRyvieId()` qui ne supprimait que le RyvieId.

**Solution** : Appelle maintenant `clearAllData()` qui supprime TOUT.

```dart
// AVANT (ligne 84-86)
// Réinitialiser le ryvieId
await ref.read(authProvider.notifier).resetRyvieId();

// APRÈS (ligne 84-85)
// Effacer TOUTES les données (y compris ryvieId, tunnelHost, publicUrl)
await ref.read(authProvider.notifier).clearAllData();
```

---

### 4. `/mobile/lib/services/smart_url_selector.service.dart`

**Amélioration** : Récupère maintenant aussi le `ryvieId` lors de la récupération des infos tunnel.

```dart
// AVANT (ligne 59-64)
final tunnelHost = data['tunnelHost'] as String?;
final publicUrl = data['publicUrl'] as String?;

// Ne sauvegarder que tunnelHost et publicUrl, PAS le ryvieId
await saveTunnelInfo(tunnelHost: tunnelHost, publicUrl: publicUrl);

// APRÈS (ligne 59-64)
final ryvieId = data['ryvieId'] as String?;
final tunnelHost = data['tunnelHost'] as String?;
final publicUrl = data['publicUrl'] as String?;

// Sauvegarder toutes les informations du tunnel
await saveTunnelInfo(ryvieId: ryvieId, tunnelHost: tunnelHost, publicUrl: publicUrl);
```

---

## 🎯 Comportement attendu

### Scénario 1 : Première connexion

1. L'app essaie `ryvie.local:3013`
2. Si succès → Récupère et sauvegarde `ryvieId`, `tunnelHost`, `publicUrl`
3. Si échec → Utilise l'URL tunnel sauvegardée (si disponible)

### Scénario 2 : Déconnexion (bouton "Se déconnecter")

1. L'utilisateur clique sur "Se déconnecter"
2. Confirmation : "Voulez-vous vous déconnecter ?"
3. Si OUI → Supprime token/données MAIS garde `ryvieId`, `tunnelHost`, `publicUrl`
4. Retour à l'écran de login
5. Reconnexion facile : L'app se connecte automatiquement avec les infos sauvegardées

### Scénario 3 : Changement de serveur (bouton "Changer de Ryvie")

1. L'utilisateur clique sur "Changer de Ryvie"
2. Avertissement : "Votre ancienne connexion sera perdue"
3. Si CONTINUER → Supprime TOUT (`ryvieId`, `tunnelHost`, `publicUrl`, token, données)
4. Retour à l'écran de login
5. Comme une première connexion : L'app doit être sur le WiFi du nouveau Ryvie

### Scénario 4 : Détection de RyvieId différent

1. L'app se connecte à `ryvie.local:3013`
2. Le RyvieId reçu ≠ RyvieId sauvegardé
3. Basculement automatique vers le tunnel
4. Si tunnel indisponible → Message d'erreur

---

## ✅ Tests à effectuer

### Test 1 : Déconnexion garde les infos

1. Se connecter à un Ryvie
2. Vérifier que `ryvieId`, `tunnelHost`, `publicUrl` sont sauvegardés
3. Se déconnecter
4. Vérifier que `ryvieId`, `tunnelHost`, `publicUrl` sont TOUJOURS là
5. Se reconnecter → Doit fonctionner automatiquement

### Test 2 : Changement de serveur supprime tout

1. Se connecter à un Ryvie
2. Vérifier que `ryvieId`, `tunnelHost`, `publicUrl` sont sauvegardés
3. Cliquer sur "Changer de Ryvie" → Confirmer
4. Vérifier que `ryvieId`, `tunnelHost`, `publicUrl` sont SUPPRIMÉS
5. Se reconnecter → Doit demander de se connecter au WiFi du nouveau Ryvie

### Test 3 : Fallback automatique vers tunnel

1. Se connecter en local (WiFi)
2. Désactiver le WiFi
3. L'app doit basculer automatiquement vers le tunnel
4. Vérifier que l'app fonctionne via Internet

### Test 4 : Détection de RyvieId différent

1. Se connecter à un Ryvie A
2. Se connecter au WiFi d'un Ryvie B (sans changer de serveur)
3. L'app doit détecter le RyvieId différent
4. L'app doit basculer automatiquement vers le tunnel du Ryvie A

---

## 📝 Notes importantes

- **RyvieId** : Identifiant unique de la machine Ryvie (comme un numéro de série)
- **TunnelHost** : Adresse IP du tunnel (ex: `abc123.ryvie.app`)
- **PublicUrl** : URL complète publique (ex: `http://abc123.ryvie.app:3013`)

Ces 3 informations sont récupérées automatiquement depuis l'API locale :

```
GET http://ryvie.local:3002/api/settings/ryvie-domains
```

Réponse :

```json
{
  "success": true,
  "ryvieId": "abc123...",
  "tunnelHost": "abc123.ryvie.app",
  "publicUrl": "http://abc123.ryvie.app:3013"
}
```
