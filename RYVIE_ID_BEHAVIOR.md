# Comportement du RyvieId et changement de Ryvie

## Vue d'ensemble

Le système de **RyvieId** permet à l'application mobile de détecter automatiquement si l'utilisateur est connecté à son propre Ryvie (connexion locale) ou à un autre Ryvie (nécessite le tunnel).

## Fonctionnement automatique

### 1. Première connexion

- L'utilisateur se connecte au WiFi de son Ryvie
- L'app détecte `ryvie.local:3013` et récupère le `ryvieId` du serveur
- Le `ryvieId` est **sauvegardé automatiquement** dans le Store local
- La connexion locale est établie

### 2. Connexion ultérieure chez soi

- L'app détecte `ryvie.local:3013`
- Compare le `ryvieId` du serveur avec celui sauvegardé
- **Si identique** → connexion locale rapide ✅
- **Si différent** → voir section suivante

### 3. Connexion sur un autre réseau WiFi avec un Ryvie différent

**Comportement automatique (sans intervention utilisateur) :**

1. L'app détecte `ryvie.local:3013` mais le `ryvieId` ne correspond pas
2. **Basculement automatique vers le tunnel** de l'utilisateur
3. Aucun dialogue, aucun blocage
4. L'utilisateur continue normalement via son tunnel

**Cas d'erreur :**

- Si le tunnel n'est pas configuré → message d'erreur explicite
- Si le tunnel est inaccessible → message d'erreur avec retry automatique

### 4. Connexion depuis l'extérieur (pas de WiFi local)

- L'app ne détecte pas `ryvie.local`
- Utilise automatiquement le tunnel configuré
- Pas de vérification de `ryvieId` (car connexion distante)

## Changer de Ryvie

### Cas d'usage

Un utilisateur veut se connecter à un **nouveau Ryvie** (déménagement, nouveau serveur, etc.)

### Procédure

1. **Se connecter au WiFi du nouveau Ryvie**
2. **Ouvrir l'application et se connecter**
3. **Sur la page de login, cliquer sur "Changer de Ryvie"**
4. **Lire l'avertissement :**
   - "Pour vous connecter à un nouveau Ryvie, vous devez être sur le même réseau WiFi que ce Ryvie"
   - "⚠️ Votre ancienne connexion sera perdue"
5. **Cliquer sur "Continuer"**
6. Le `ryvieId` est réinitialisé
7. Se reconnecter → le nouveau `ryvieId` sera sauvegardé automatiquement

### Important

- L'utilisateur **reste connecté** (email/password conservés)
- Seul le `ryvieId` est réinitialisé
- Il **doit être sur le réseau local** du nouveau Ryvie pour que la détection fonctionne

## Architecture technique

### Fichiers modifiés

#### 1. `server_health_check.provider.dart`

**Responsabilité :** Vérifier la santé du serveur et gérer le basculement automatique

**Modifications :**

- Suppression de `_pendingRyvieId` et des méthodes associées
- Basculement automatique vers le tunnel en cas de mismatch de `ryvieId`
- Pas de dialogue, pas de blocage

**Code clé :**

```dart
if (e.toString().contains('RYVIE_ID_MISMATCH:')) {
  // Basculer vers le tunnel automatiquement
  final tunnelUrl = await authNotifier.setOpenApiServiceEndpoint(forceTunnel: true);
  if (tunnelUrl != null) {
    _ref.read(connectionStatusProvider.notifier).setConnected(tunnelUrl);
    return; // Health check terminé avec succès via tunnel
  }
}
```

#### 2. `auth.service.dart`

**Responsabilité :** Gérer l'authentification et les informations de connexion

**Ajout :**

```dart
/// Réinitialise uniquement le ryvieId pour permettre de changer de Ryvie
Future<void> resetRyvieId() async {
  _log.info('🔄 Réinitialisation du RyvieId pour changement de Ryvie');
  await Store.delete(StoreKey.ryvieId);
}
```

#### 3. `auth.provider.dart`

**Responsabilité :** Exposer les méthodes d'authentification aux widgets

**Ajout :**

```dart
Future<void> resetRyvieId() {
  return _authService.resetRyvieId();
}
```

#### 4. `login_form.dart`

**Responsabilité :** Interface de connexion

**Ajouts :**

- Bouton "Changer de Ryvie" (discret, en bas de la page de login)
- Dialogue d'avertissement avec confirmation
- Message de succès après réinitialisation

**Code clé :**

```dart
void _showChangeRyvieDialog(BuildContext context, WidgetRef ref) {
  showDialog(
    context: context,
    builder: (context) => AlertDialog(
      icon: const Icon(Icons.warning_amber_rounded, size: 48, color: Colors.orange),
      title: const Text('Changer de Ryvie'),
      content: const Text(
        'Pour vous connecter à un nouveau Ryvie, vous devez être sur le même réseau WiFi que ce Ryvie.\n\n'
        '⚠️ Votre ancienne connexion sera perdue.'
      ),
      actions: [
        TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Annuler')),
        FilledButton(
          onPressed: () async {
            await ref.read(authProvider.notifier).resetRyvieId();
            ImmichToast.show(context: context, msg: 'RyvieId réinitialisé...');
          },
          child: const Text('Continuer'),
        ),
      ],
    ),
  );
}
```

#### 5. `connection_error_banner.dart`

**Responsabilité :** Afficher les erreurs de connexion

**Modifications :**

- Suppression de toute la logique de dialogue pour le mismatch de `ryvieId`
- Simplification (plus besoin de gérer le cas spécial)
- Nettoyage des imports inutilisés

#### 6. `ryvie_id_mismatch_dialog.dart`

**Supprimé** - Plus nécessaire avec le basculement automatique

### Flow de données

```
┌─────────────────────────────────────────────────────────────┐
│                    Démarrage de l'app                        │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │ performHealthCheck()  │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │ Détection ryvie.local?│
              └───────────┬───────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
    ┌──────────────┐          ┌──────────────────┐
    │ OUI (local)  │          │ NON (distant)    │
    └──────┬───────┘          └────────┬─────────┘
           │                           │
           ▼                           ▼
┌──────────────────────┐    ┌──────────────────────┐
│ Vérifier ryvieId     │    │ Utiliser tunnel      │
└──────┬───────────────┘    │ (pas de vérif)       │
       │                    └──────────────────────┘
       │
┌──────┴──────┐
│             │
▼             ▼
┌─────────┐   ┌─────────────────┐
│ Match   │   │ Mismatch        │
└────┬────┘   └────┬────────────┘
     │             │
     ▼             ▼
┌─────────┐   ┌──────────────────────┐
│ Local   │   │ Basculer tunnel AUTO │
│ OK ✅   │   │ (sans dialogue)      │
└─────────┘   └──────────────────────┘
```

## Avantages de cette approche

1. **Transparence pour l'utilisateur**

   - Pas de dialogue intrusif
   - Basculement automatique et silencieux
   - L'app fonctionne partout sans intervention

2. **Sécurité**

   - Le `ryvieId` garantit qu'on se connecte au bon serveur en local
   - Le tunnel est utilisé automatiquement si nécessaire

3. **Flexibilité**

   - Possibilité de changer de Ryvie via le bouton dédié
   - Avertissement clair des conséquences

4. **Performance**
   - Connexion locale privilégiée quand disponible
   - Pas de tentatives inutiles si le `ryvieId` ne correspond pas

## Tests recommandés

### Scénario 1 : Première connexion

1. Installer l'app
2. Se connecter au WiFi du Ryvie
3. Se connecter → le `ryvieId` doit être sauvegardé
4. Vérifier les logs : `✅ Premier RyvieId sauvegardé: xxx`

### Scénario 2 : Connexion chez soi

1. Ouvrir l'app
2. Vérifier les logs : `✅ RyvieId correspond: xxx`
3. Connexion locale établie

### Scénario 3 : Connexion chez quelqu'un d'autre avec un Ryvie

1. Se connecter au WiFi d'un ami qui a un Ryvie
2. Ouvrir l'app
3. Vérifier les logs : `⚠️ RyvieId différent détecté` puis `🔄 Basculement automatique vers le tunnel`
4. L'app doit fonctionner normalement via le tunnel

### Scénario 4 : Changer de Ryvie

1. Se connecter au WiFi du nouveau Ryvie
2. Aller sur la page de login
3. Cliquer sur "Changer de Ryvie"
4. Lire l'avertissement et confirmer
5. Se reconnecter → le nouveau `ryvieId` doit être sauvegardé

### Scénario 5 : Connexion depuis l'extérieur

1. Désactiver le WiFi (utiliser 4G/5G)
2. Ouvrir l'app
3. Le tunnel doit être utilisé automatiquement
4. Pas de vérification de `ryvieId`

## Logs utiles pour le debug

```
🏥 Lancement du health check au démarrage
🔍 Connexion locale détectée, vérification du ryvieId...
📦 RyvieId sauvegardé: xxx
✅ RyvieId validé pour connexion locale
```

Ou en cas de mismatch :

```
⚠️ RyvieId différent détecté: yyy (attendu: xxx)
🔄 Basculement automatique vers le tunnel...
✅ Basculement réussi vers le tunnel: https://xxx.tunnel.com
```

## Notes importantes

- Le `ryvieId` n'est vérifié **que pour les connexions locales** (`ryvie.local`)
- Les connexions via tunnel ne vérifient **jamais** le `ryvieId`
- Le basculement est **toujours automatique** et **silencieux**
- L'utilisateur n'est **jamais déconnecté** automatiquement
- Le bouton "Changer de Ryvie" est la **seule façon** de réinitialiser le `ryvieId`
