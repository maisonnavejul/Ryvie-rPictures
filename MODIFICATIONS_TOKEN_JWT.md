# Modifications - Authentification JWT pour récupération infos tunnel

## 📋 Résumé

L'API Ryvie a changé : l'endpoint `/api/settings/ryvie-domains` nécessite maintenant un token JWT pour l'authentification. J'ai modifié le code pour :

1. ✅ Utiliser le token d'authentification rPictures pour récupérer les infos tunnel
2. ✅ Ajouter des logs détaillés pour voir toutes les informations récupérées
3. ✅ Récupérer automatiquement les infos après chaque login réussi

---

## 🔧 Fichiers modifiés

### 1. `/mobile/lib/services/smart_url_selector.service.dart`

**Modifications de `fetchAndSaveTunnelInfo()`** :

#### Avant

```dart
Future<void> fetchAndSaveTunnelInfo() async {
  // Pas d'authentification
  final request = await client.getUrl(uri);
  final response = await request.close();
  // ...
}
```

#### Après

```dart
Future<void> fetchAndSaveTunnelInfo({String? accessToken}) async {
  // Récupérer le token du Store si non fourni
  final token = accessToken ?? Store.tryGet(StoreKey.accessToken);

  if (token == null || token.isEmpty) {
    _log.warning('⚠️  Pas de token JWT disponible');
    return;
  }

  _log.info('🔑 Token JWT trouvé - longueur: ${token.length} caractères');

  final request = await client.getUrl(uri);

  // Ajouter le header Authorization
  request.headers.set('Authorization', 'Bearer $token');
  _log.info('📤 Envoi requête avec Authorization header');

  final response = await request.close();
  _log.info('📥 Réponse reçue - Status: ${response.statusCode}');

  if (response.statusCode == 200) {
    final responseBody = await response.transform(utf8.decoder).join();
    _log.info('📦 Body de la réponse: $responseBody');

    final data = json.decode(responseBody);

    if (data['success'] == true) {
      final ryvieId = data['ryvieId'] as String?;
      final tunnelHost = data['tunnelHost'] as String?;
      final publicUrl = data['publicUrl'] as String?;
      final setupKey = data['setupKey'] as String?;

      // LOGS DÉTAILLÉS
      _log.info('✅ Données parsées avec succès:');
      _log.info('   📋 setupKey: ${setupKey ?? "N/A"}');
      _log.info('   🆔 ryvieId: ${ryvieId ?? "N/A"}');
      _log.info('   🌐 tunnelHost: ${tunnelHost ?? "N/A"}');
      _log.info('   🔗 publicUrl: ${publicUrl ?? "N/A"}');

      await saveTunnelInfo(ryvieId: ryvieId, tunnelHost: tunnelHost, publicUrl: publicUrl);
    }
  } else if (response.statusCode == 401) {
    _log.severe('❌ Erreur 401 Unauthorized - Token JWT invalide ou expiré');
  } else if (response.statusCode == 403) {
    _log.severe('❌ Erreur 403 Forbidden - Accès refusé');
  }
}
```

**Nouveaux logs ajoutés** :

- 🔑 Token JWT trouvé avec sa longueur
- 📤 Confirmation d'envoi de la requête avec Authorization
- 📥 Status HTTP de la réponse
- 📦 Body complet de la réponse JSON
- 📋 setupKey récupéré
- 🆔 ryvieId récupéré
- 🌐 tunnelHost (IP du tunnel) récupéré
- 🔗 publicUrl récupéré
- ❌ Erreurs 401/403 spécifiques

---

### 2. `/mobile/lib/providers/auth.provider.dart`

**Ajout de l'import** :

```dart
import 'package:immich_mobile/services/smart_url_selector.service.dart';
```

**Nouvelle méthode `_fetchTunnelInfoAfterLogin()`** :

```dart
/// Récupère les informations du tunnel après un login réussi
void _fetchTunnelInfoAfterLogin(String accessToken) {
  try {
    final smartUrlSelector = SmartUrlSelectorService();
    smartUrlSelector.fetchAndSaveTunnelInfo(accessToken: accessToken).catchError((e) {
      _log.warning('Erreur lors de la récupération des infos tunnel après login: $e');
    });
  } catch (e) {
    _log.warning('Erreur lors de l\'initialisation de la récupération des infos tunnel: $e');
  }
}
```

**Modification de `saveAuthInfo()`** :

```dart
Future<bool> saveAuthInfo({required String accessToken}) async {
  // ... code existant ...

  state = state.copyWith(
    deviceId: deviceId,
    userId: user.id,
    userEmail: user.email,
    isAuthenticated: true,
    name: user.name,
    isAdmin: user.isAdmin,
  );

  // ✅ NOUVEAU : Récupérer les informations du tunnel après un login réussi
  _fetchTunnelInfoAfterLogin(accessToken);

  return true;
}
```

---

## 📊 Flux de récupération des infos tunnel

### Scénario 1 : Login réussi

```
1. Utilisateur se connecte avec email/password
   ↓
2. rPictures envoie POST /api/auth/login
   ↓
3. Serveur retourne { accessToken: "eyJhbG..." }
   ↓
4. saveAuthInfo() sauvegarde le token dans Store
   ↓
5. _fetchTunnelInfoAfterLogin() est appelé
   ↓
6. GET /api/settings/ryvie-domains
   Header: Authorization: Bearer eyJhbG...
   ↓
7. Serveur retourne:
   {
     "success": true,
     "setupKey": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
     "tunnelHost": "100.64.0.5",
     "ryvieId": "ryvie-abc123def456",
     "publicUrl": "http://100.64.0.5:3013"
   }
   ↓
8. Infos sauvegardées dans Store:
   - StoreKey.ryvieId = "ryvie-abc123def456"
   - StoreKey.tunnelHost = "100.64.0.5"
   - StoreKey.publicUrl = "http://100.64.0.5:3013"
```

### Scénario 2 : Connexion locale détectée

```
1. App démarre et détecte ryvie.local:3013
   ↓
2. selectServerUrl() retourne (url: "http://ryvie.local:3013", isLocal: true)
   ↓
3. fetchAndSaveTunnelInfo() est appelé en arrière-plan
   ↓
4. Récupère le token du Store (déjà sauvegardé lors du login précédent)
   ↓
5. GET /api/settings/ryvie-domains avec Authorization header
   ↓
6. Infos tunnel récupérées et sauvegardées
```

---

## 🎯 Logs à surveiller

Lors du login, tu devrais voir dans les logs :

```
[SmartUrlSelectorService] 🔄 Récupération automatique des informations du tunnel...
[SmartUrlSelectorService] 🔑 Token JWT trouvé - longueur: 245 caractères
[SmartUrlSelectorService] 📤 Envoi requête à: http://ryvie.local:3002/api/settings/ryvie-domains avec Authorization header
[SmartUrlSelectorService] 📥 Réponse reçue - Status: 200
[SmartUrlSelectorService] 📦 Body de la réponse: {"success":true,"setupKey":"...","tunnelHost":"100.64.0.5","ryvieId":"ryvie-abc123","publicUrl":"http://100.64.0.5:3013"}
[SmartUrlSelectorService] ✅ Données parsées avec succès:
[SmartUrlSelectorService]    📋 setupKey: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
[SmartUrlSelectorService]    🆔 ryvieId: ryvie-abc123def456
[SmartUrlSelectorService]    🌐 tunnelHost: 100.64.0.5
[SmartUrlSelectorService]    🔗 publicUrl: http://100.64.0.5:3013
[SmartUrlSelectorService] RyvieId sauvegardé: ryvie-abc123def456
[SmartUrlSelectorService] TunnelHost sauvegardé: 100.64.0.5
[SmartUrlSelectorService] PublicUrl sauvegardée: http://100.64.0.5:3013
[SmartUrlSelectorService] ✅ Informations du tunnel récupérées et sauvegardées automatiquement:
   - ryvieId: ryvie-abc123def456
   - tunnelHost: 100.64.0.5
   - publicUrl: http://100.64.0.5:3013
```

### En cas d'erreur 401 (token invalide)

```
[SmartUrlSelectorService] 📥 Réponse reçue - Status: 401
[SmartUrlSelectorService] ❌ Erreur 401 Unauthorized - Token JWT invalide ou expiré
```

### En cas d'erreur 403 (accès refusé)

```
[SmartUrlSelectorService] 📥 Réponse reçue - Status: 403
[SmartUrlSelectorService] ❌ Erreur 403 Forbidden - Accès refusé
```

### Si pas de token disponible

```
[SmartUrlSelectorService] 🔄 Récupération automatique des informations du tunnel...
[SmartUrlSelectorService] ⚠️  Pas de token JWT disponible - impossible de récupérer les infos tunnel
```

---

## ✅ Tests à effectuer

### Test 1 : Login et récupération des infos

1. Lance l'app
2. Connecte-toi avec email/password
3. Vérifie dans les logs que tu vois :
   - 🔑 Token JWT trouvé
   - 📦 Body de la réponse avec les 4 champs
   - ✅ Infos sauvegardées

### Test 2 : Vérifier les valeurs récupérées

Dans les logs, tu dois voir :

- **setupKey** : UUID au format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
- **ryvieId** : Commence par "ryvie-" suivi d'un hash
- **tunnelHost** : IP dans la plage 100.64.x.x
- **publicUrl** : URL complète http://100.64.x.x:3013

### Test 3 : Déconnexion et reconnexion

1. Déconnecte-toi
2. Les infos tunnel doivent être GARDÉES (pas supprimées)
3. Reconnecte-toi
4. Les infos doivent être mises à jour

### Test 4 : Changement de Ryvie

1. Clique sur "Changer de Ryvie"
2. Les infos tunnel doivent être SUPPRIMÉES
3. Connecte-toi à un nouveau Ryvie
4. De nouvelles infos doivent être récupérées

---

## 🔍 Comment voir les logs

### Option 1 : Via Xcode Console

1. Ouvre Xcode
2. Window → Devices and Simulators
3. Sélectionne ton simulateur
4. Clique sur "Open Console"
5. Filtre par "SmartUrlSelector" ou "ryvie"

### Option 2 : Via Flutter run

```bash
cd /Users/jules/Desktop/Ryvie-rPictures/mobile
flutter run -d 9F02DEFC-40C1-4CD8-8079-D318E991979E
```

Tous les logs s'afficheront dans le terminal.

---

## 📝 Notes importantes

1. **Token JWT** : Le même token utilisé pour l'authentification rPictures est utilisé pour récupérer les infos tunnel
2. **Sécurité** : Le token est stocké dans `StoreKey.accessToken` et récupéré automatiquement
3. **Logs détaillés** : Tous les logs incluent des emojis pour faciliter la lecture :
   - 🔑 = Token
   - 📤 = Requête envoyée
   - 📥 = Réponse reçue
   - 📦 = Body JSON
   - ✅ = Succès
   - ❌ = Erreur
   - ⚠️ = Avertissement
4. **Réponse API** : La réponse contient maintenant 4 champs au lieu de 3 :
   - `setupKey` (nouveau)
   - `ryvieId`
   - `tunnelHost`
   - `publicUrl`

---

## 🚀 Prochaines étapes

1. Rebuild l'app pour appliquer les modifications
2. Connecte-toi et vérifie les logs
3. Confirme que tu vois bien :
   - Le setupKey
   - Le ryvieId
   - Le tunnelHost (IP du tunnel)
   - Le publicUrl

Les modifications sont prêtes ! 🎉
