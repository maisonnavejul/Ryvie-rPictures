# Correction - Utilisation de l'API Ryvie pour récupérer les infos tunnel

## 🐛 Problème identifié

**Erreur** : `ApiException 401: {"message":"Invalid user token","error":"Unauthorized","statusCode":401}`

**Cause** : J'utilisais le token JWT de **rPictures** (Immich, port 3013) pour appeler l'API **Ryvie** (port 3002). Ce sont deux APIs différentes avec deux systèmes d'authentification séparés !

## ✅ Solution implémentée

### Flux correct d'authentification

```
1. Login rPictures (Immich)
   ↓
   POST http://ryvie.local:3013/api/auth/login
   Body: { "email": "...", "password": "..." }
   → Token JWT rPictures

2. Login Ryvie (en parallèle)
   ↓
   POST http://ryvie.local:3002/api/authenticate
   Body: { "uid": "...", "password": "..." }
   → Token JWT Ryvie

3. Récupération infos tunnel
   ↓
   GET http://ryvie.local:3002/api/settings/ryvie-domains
   Header: Authorization: Bearer <TOKEN_JWT_RYVIE>
   → ryvieId, tunnelHost, publicUrl, setupKey
```

## 📁 Fichiers créés/modifiés

### 1. **Nouveau fichier** : `/mobile/lib/services/ryvie_api.service.dart`

Service dédié pour communiquer avec l'API Ryvie (port 3002).

**Méthodes principales** :

#### `authenticate(uid, password)`

- Authentifie l'utilisateur sur l'API Ryvie
- Endpoint : `POST http://ryvie.local:3002/api/authenticate`
- Body : `{ "uid": "<email>", "password": "<password>" }`
- Retourne : Token JWT Ryvie

```dart
Future<String?> authenticate({required String uid, required String password}) async {
  final uri = Uri.parse('$localRyvieApiUrl/api/authenticate');
  final client = HttpClient();

  final request = await client.postUrl(uri);
  request.headers.set('Content-Type', 'application/json');

  final body = json.encode({
    'uid': uid,
    'password': password,
  });

  request.write(body);
  final response = await request.close();
  final responseBody = await response.transform(utf8.decoder).join();

  if (response.statusCode == 200) {
    final data = json.decode(responseBody);
    // La réponse contient directement le token
    final token = data['token'] as String?;
    return token;
  }

  return null;
}
```

#### `fetchTunnelInfo(ryvieToken)`

- Récupère les infos tunnel avec le token JWT Ryvie
- Endpoint : `GET http://ryvie.local:3002/api/settings/ryvie-domains`
- Header : `Authorization: Bearer <ryvieToken>`
- Retourne : `(ryvieId, tunnelHost, publicUrl, setupKey)`

```dart
Future<({String? ryvieId, String? tunnelHost, String? publicUrl, String? setupKey})>
    fetchTunnelInfo({required String ryvieToken}) async {

  final uri = Uri.parse('$localRyvieApiUrl/api/settings/ryvie-domains');
  final client = HttpClient();

  final request = await client.getUrl(uri);
  request.headers.set('Authorization', 'Bearer $ryvieToken');

  final response = await request.close();
  final responseBody = await response.transform(utf8.decoder).join();

  if (response.statusCode == 200) {
    final data = json.decode(responseBody);
    if (data['success'] == true) {
      return (
        ryvieId: data['ryvieId'],
        tunnelHost: data['tunnelHost'],
        publicUrl: data['publicUrl'],
        setupKey: data['setupKey'],
      );
    }
  }

  return (ryvieId: null, tunnelHost: null, publicUrl: null, setupKey: null);
}
```

#### `authenticateAndFetchTunnelInfo(uid, password)`

- Combine les deux opérations en une seule
- Authentifie sur Ryvie → Récupère les infos tunnel → Sauvegarde dans Store

```dart
Future<({String? ryvieId, String? tunnelHost, String? publicUrl, String? setupKey})>
    authenticateAndFetchTunnelInfo({required String uid, required String password}) async {

  // Étape 1 : Authentification sur l'API Ryvie
  final ryvieToken = await authenticate(uid: uid, password: password);

  if (ryvieToken == null) {
    return (ryvieId: null, tunnelHost: null, publicUrl: null, setupKey: null);
  }

  // Étape 2 : Récupération des infos tunnel avec le token Ryvie
  final tunnelInfo = await fetchTunnelInfo(ryvieToken: ryvieToken);

  if (tunnelInfo.ryvieId != null) {
    // Sauvegarder les informations
    await _saveTunnelInfo(
      ryvieId: tunnelInfo.ryvieId,
      tunnelHost: tunnelInfo.tunnelHost,
      publicUrl: tunnelInfo.publicUrl,
    );
  }

  return tunnelInfo;
}
```

---

### 2. **Modifié** : `/mobile/lib/providers/auth.provider.dart`

#### Import ajouté

```dart
import 'package:immich_mobile/services/ryvie_api.service.dart';
```

#### Méthode `login()` modifiée

```dart
Future<LoginResponse> login(String email, String password) async {
  final response = await _authService.login(email, password);
  await saveAuthInfo(accessToken: response.accessToken);

  // Après le login rPictures réussi, récupérer les infos tunnel via l'API Ryvie
  _fetchTunnelInfoViaRyvieApi(email, password);

  return response;
}
```

#### Nouvelle méthode `_fetchTunnelInfoViaRyvieApi()`

```dart
/// Récupère les informations du tunnel via l'API Ryvie après un login réussi
/// Utilise les mêmes credentials (email/password) pour s'authentifier sur l'API Ryvie
void _fetchTunnelInfoViaRyvieApi(String email, String password) {
  try {
    _log.info('🔄 Lancement récupération infos tunnel via API Ryvie');

    final ryvieApiService = RyvieApiService();
    ryvieApiService.authenticateAndFetchTunnelInfo(
      uid: email,
      password: password,
    ).then((tunnelInfo) {
      if (tunnelInfo.ryvieId != null) {
        _log.info('✅ Infos tunnel récupérées avec succès via API Ryvie');
        _log.info('   🆔 RyvieId: ${tunnelInfo.ryvieId}');
        _log.info('   🌐 TunnelHost: ${tunnelInfo.tunnelHost}');
        _log.info('   🔗 PublicUrl: ${tunnelInfo.publicUrl}');
      } else {
        _log.warning('⚠️  Échec de la récupération des infos tunnel via API Ryvie');
      }
    }).catchError((e) {
      _log.warning('❌ Erreur lors de la récupération des infos tunnel via API Ryvie: $e');
    });
  } catch (e) {
    _log.warning('❌ Erreur lors de l\'initialisation de la récupération des infos tunnel: $e');
  }
}
```

---

## 🔄 Flux complet lors du login

```
Utilisateur entre email + password
         ↓
┌────────────────────────────────────────────────┐
│  AuthNotifier.login(email, password)           │
└────────────────────────────────────────────────┘
         ↓
┌────────────────────────────────────────────────┐
│  1. Login rPictures (Immich)                   │
│     POST http://ryvie.local:3013/api/auth/login│
│     Body: { "email": "...", "password": "..." }│
│     → Token JWT rPictures                      │
└────────────────────────────────────────────────┘
         ↓
┌────────────────────────────────────────────────┐
│  2. Sauvegarde token rPictures                 │
│     saveAuthInfo(accessToken)                  │
└────────────────────────────────────────────────┘
         ↓
┌────────────────────────────────────────────────┐
│  3. Récupération infos tunnel (en parallèle)   │
│     _fetchTunnelInfoViaRyvieApi(email, pass)   │
└────────────────────────────────────────────────┘
         ↓
┌────────────────────────────────────────────────┐
│  3.1. Login Ryvie                              │
│       POST http://ryvie.local:3002/api/auth/   │
│            login                               │
│       Body: { "uid": "...", "password": "..." }│
│       → Token JWT Ryvie                        │
└────────────────────────────────────────────────┘
         ↓
┌────────────────────────────────────────────────┐
│  3.2. Récupération infos tunnel                │
│       GET http://ryvie.local:3002/api/settings/│
│           ryvie-domains                        │
│       Header: Authorization: Bearer <TOKEN>    │
│       → ryvieId, tunnelHost, publicUrl         │
└────────────────────────────────────────────────┘
         ↓
┌────────────────────────────────────────────────┐
│  3.3. Sauvegarde dans Store                    │
│       StoreKey.ryvieId = "ryvie-abc123..."     │
│       StoreKey.tunnelHost = "100.64.0.5"       │
│       StoreKey.publicUrl = "http://100.64..."  │
└────────────────────────────────────────────────┘
```

---

## 🎯 Logs attendus

### Lors du login réussi

```
[AuthNotifier] 🔄 Lancement récupération infos tunnel via API Ryvie
[RyvieApiService] 🚀 Démarrage authentification Ryvie + récupération infos tunnel
[RyvieApiService] 🔐 Authentification sur l'API Ryvie...
[RyvieApiService]    URL: http://ryvie.local:3002/api/authenticate
[RyvieApiService]    UID: user@example.com
[RyvieApiService] 📤 Envoi de la requête d'authentification...
[RyvieApiService] 📥 Réponse reçue - Status: 200
[RyvieApiService] 📦 Body: {"message":"Authentification réussie","user":{...},"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","expiresIn":3600}
[RyvieApiService] ✅ Authentification Ryvie réussie !
[RyvieApiService] 🔑 Token JWT Ryvie reçu - longueur: 245 caractères
[RyvieApiService] 👤 User: John Doe
[RyvieApiService] 📧 Email: user@example.com
[RyvieApiService] 🔄 Récupération des informations du tunnel avec token Ryvie...
[RyvieApiService] 📤 Envoi requête à: http://ryvie.local:3002/api/settings/ryvie-domains
[RyvieApiService] 🔑 Avec token Ryvie JWT - longueur: 245 caractères
[RyvieApiService] 📥 Réponse reçue - Status: 200
[RyvieApiService] 📦 Body de la réponse: {"success":true,"setupKey":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX","tunnelHost":"100.64.0.5","ryvieId":"ryvie-abc123def456","publicUrl":"http://100.64.0.5:3013"}
[RyvieApiService] ✅ Données parsées avec succès:
[RyvieApiService]    📋 setupKey: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
[RyvieApiService]    🆔 ryvieId: ryvie-abc123def456
[RyvieApiService]    🌐 tunnelHost: 100.64.0.5
[RyvieApiService]    🔗 publicUrl: http://100.64.0.5:3013
[RyvieApiService] 💾 Sauvegarde des informations de tunnel
[RyvieApiService]    ✅ RyvieId sauvegardé: ryvie-abc123def456
[RyvieApiService]    ✅ TunnelHost sauvegardé: 100.64.0.5
[RyvieApiService]    ✅ PublicUrl sauvegardée: http://100.64.0.5:3013
[AuthNotifier] ✅ Infos tunnel récupérées avec succès via API Ryvie
[AuthNotifier]    🆔 RyvieId: ryvie-abc123def456
[AuthNotifier]    🌐 TunnelHost: 100.64.0.5
[AuthNotifier]    🔗 PublicUrl: http://100.64.0.5:3013
```

### En cas d'erreur d'authentification Ryvie

```
[RyvieApiService] 🔐 Authentification sur l'API Ryvie...
[RyvieApiService] 📥 Réponse reçue - Status: 401
[RyvieApiService] ❌ Erreur 401 - Credentials invalides
[AuthNotifier] ⚠️  Échec de la récupération des infos tunnel via API Ryvie
```

---

## 🔑 Points clés

1. **Deux APIs distinctes** :
   - **rPictures (Immich)** : Port 3013, token JWT pour les photos
   - **Ryvie** : Port 3002, token JWT pour les infos système/tunnel

2. **Mêmes credentials** :
   - L'utilisateur utilise le même email/password pour les deux APIs
   - Mais chaque API génère son propre token JWT

3. **Authentification séquentielle** :
   - D'abord login rPictures (bloquant)
   - Puis login Ryvie (asynchrone en arrière-plan)

4. **Logs détaillés** :
   - Chaque étape est loggée avec des emojis
   - Permet de suivre le flux complet
   - Facilite le debugging

---

## ✅ Tests à effectuer

1. **Login normal**
   - Entre email/password
   - Vérifie les logs de connexion rPictures
   - Vérifie les logs de connexion Ryvie
   - Vérifie que les 4 champs sont récupérés

2. **Vérifier les données sauvegardées**
   - ryvieId doit commencer par "ryvie-"
   - tunnelHost doit être une IP 100.64.x.x
   - publicUrl doit être http://100.64.x.x:3013

3. **Erreur réseau**
   - Déconnecte le réseau
   - Vérifie que l'erreur est bien loggée
   - Vérifie que l'app ne crash pas

---

## 🚀 Prochaines étapes

1. Rebuild l'app
2. Connecte-toi avec tes credentials
3. Vérifie les logs dans la console
4. Confirme que tu vois :
   - ✅ Authentification Ryvie réussie
   - 🔑 Token JWT Ryvie reçu
   - 📋 setupKey
   - 🆔 ryvieId
   - 🌐 tunnelHost
   - 🔗 publicUrl

La correction est prête ! 🎉
