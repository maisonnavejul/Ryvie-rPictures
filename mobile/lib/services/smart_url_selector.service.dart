import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:logging/logging.dart';

/// Service pour la sélection intelligente de l'URL du serveur
/// Inspiré de Ryvie-Desktop: essaie ryvie.local:3000 en premier,
/// puis utilise l'adresse publique du tunnel si la connexion locale échoue
class SmartUrlSelectorService {
  final _log = Logger('SmartUrlSelectorService');

  static const String localServerUrl = 'http://ryvie.local:3013';
  /// Endpoint complet (ryvieId + tunnelHost + publicUrl + setupKey) — nécessite un JWT.
  static const String localTunnelInfoUrl = 'http://ryvie.local:3002/api/settings/ryvie-domains';
  /// Endpoint léger qui renvoie juste le ryvieId, sans auth — utilisé pour
  /// vérifier rapidement si on est bien sur notre Ryvie.
  static const String localMachineIdUrl = 'http://ryvie.local:3002/api/machine-id';
  static const Duration connectionTimeout = Duration(seconds: 2);

  /// Teste si une URL est accessible
  Future<bool> _testUrlConnection(String url) async {
    try {
      _log.info('Test de connexion à: $url');

      final uri = Uri.parse(url);
      final client = HttpClient();
      client.connectionTimeout = connectionTimeout;

      final request = await client.getUrl(uri);
      final response = await request.close();

      client.close();

      final isAccessible = response.statusCode >= 200 && response.statusCode < 300;
      _log.info('Résultat test $url: ${isAccessible ? "✅ SUCCÈS" : "❌ ÉCHEC"} (status: ${response.statusCode})');

      return isAccessible;
    } catch (e) {
      _log.warning('Erreur lors du test de connexion à $url: $e');
      return false;
    }
  }

  /// Récupère automatiquement les informations du tunnel depuis le serveur local
  /// Nécessite un token JWT pour l'authentification
  Future<void> fetchAndSaveTunnelInfo({String? accessToken}) async {
    try {
      _log.info('🔄 Récupération automatique des informations du tunnel...');

      // Si pas de token fourni, essayer de le récupérer du Store
      final token = accessToken ?? Store.tryGet(StoreKey.accessToken);

      if (token == null || token.isEmpty) {
        _log.warning('⚠️  Pas de token JWT disponible - impossible de récupérer les infos tunnel');
        return;
      }

      _log.info('🔑 Token JWT trouvé - longueur: ${token.length} caractères');

      final uri = Uri.parse(localTunnelInfoUrl);
      final client = HttpClient();
      client.connectionTimeout = connectionTimeout;

      final request = await client.getUrl(uri);

      // Ajouter le header Authorization avec le token JWT
      request.headers.set('Authorization', 'Bearer $token');
      _log.info('📤 Envoi requête à: $localTunnelInfoUrl avec Authorization header');

      final response = await request.close();

      _log.info('📥 Réponse reçue - Status: ${response.statusCode}');

      if (response.statusCode == 200) {
        final responseBody = await response.transform(utf8.decoder).join();
        _log.info('📦 Body de la réponse: $responseBody');

        final data = json.decode(responseBody) as Map<String, dynamic>;

        if (data['success'] == true) {
          final ryvieId = data['ryvieId'] as String?;
          final tunnelHost = data['tunnelHost'] as String?;
          final publicUrl = data['publicUrl'] as String?;
          final setupKey = data['setupKey'] as String?;

          _log.info('✅ Données parsées avec succès:');
          _log.info('   📋 setupKey: ${setupKey ?? "N/A"}');
          _log.info('   🆔 ryvieId: ${ryvieId ?? "N/A"}');
          _log.info('   🌐 tunnelHost: ${tunnelHost ?? "N/A"}');
          _log.info('   🔗 publicUrl: ${publicUrl ?? "N/A"}');

          // Sauvegarder toutes les informations du tunnel
          await saveTunnelInfo(ryvieId: ryvieId, tunnelHost: tunnelHost, publicUrl: publicUrl);

          _log.info(
            '✅ Informations du tunnel récupérées et sauvegardées automatiquement:\n'
            '   - ryvieId: ${ryvieId ?? "N/A"}\n'
            '   - tunnelHost: ${tunnelHost ?? "N/A"}\n'
            '   - publicUrl: ${publicUrl ?? "N/A"}',
          );
        } else {
          _log.warning('⚠️  API retourne success=false');
          _log.warning('   Réponse complète: $responseBody');
        }
      } else if (response.statusCode == 401) {
        _log.severe('❌ Erreur 401 Unauthorized - Token JWT invalide ou expiré');
      } else if (response.statusCode == 403) {
        _log.severe('❌ Erreur 403 Forbidden - Accès refusé');
      } else {
        _log.warning('⚠️  Échec récupération infos tunnel: HTTP ${response.statusCode}');
        final responseBody = await response.transform(utf8.decoder).join();
        _log.warning('   Réponse: $responseBody');
      }

      client.close();
    } catch (e, stackTrace) {
      _log.warning('⚠️  Erreur lors de la récupération des infos tunnel: $e');
      _log.warning('   Stack trace: $stackTrace');
    }
  }

  /// Force l'utilisation de l'URL tunnel/publique (ignore le local)
  Future<({String url, bool isLocal})?> selectTunnelUrl() async {
    _log.info('=== Forçage connexion TUNNEL ===');

    // Récupérer l'URL publique sauvegardée
    final publicUrl = Store.tryGet(StoreKey.publicUrl);
    final tunnelHost = Store.tryGet(StoreKey.tunnelHost);

    _log.info('📦 Infos sauvegardées - publicUrl: ${publicUrl ?? "VIDE"}, tunnelHost: ${tunnelHost ?? "VIDE"}');

    String? urlToTry;

    if (publicUrl != null && publicUrl.isNotEmpty) {
      urlToTry = publicUrl;
      _log.info('✅ URL publique trouvée: $urlToTry');
    } else if (tunnelHost != null && tunnelHost.isNotEmpty) {
      urlToTry = 'http://$tunnelHost:3013';
      _log.info('✅ TunnelHost trouvé, construction URL: $urlToTry');
    }

    if (urlToTry != null) {
      _log.info('✅ Utilisation forcée de l\'URL TUNNEL: $urlToTry');
      return (url: urlToTry, isLocal: false);
    } else {
      _log.severe('⚠️  Aucune URL tunnel configurée');
      return null;
    }
  }

  /// Sélectionne intelligemment l'URL du serveur
  /// Retourne l'URL à utiliser et un booléen indiquant si c'est une connexion locale
  Future<({String url, bool isLocal})> selectServerUrl() async {
    _log.info('=== Démarrage sélection intelligente URL ===');

    // 1. Essayer la connexion locale en premier
    _log.info('🔍 Test connexion LOCALE: $localServerUrl');
    final localAvailable = await _testUrlConnection(localServerUrl);

    if (localAvailable) {
      // Vérifier que c'est BIEN notre Ryvie (et pas un Ryvie inconnu sur le même
      // réseau). Sans ce contrôle, on s'authentifierait contre un Ryvie étranger,
      // l'auth échouerait et le splash screen nous déloguerait — l'utilisateur
      // perçoit ça comme une déconnexion alors qu'il devrait juste basculer
      // sur le tunnel.
      final savedRyvieId = Store.tryGet(StoreKey.ryvieId);
      if (savedRyvieId != null && savedRyvieId.isNotEmpty) {
        final localRyvieId = await _fetchLocalRyvieIdQuick();
        final hasPublicFallback = _hasPublicUrlConfigured();
        final mismatch = localRyvieId != null && localRyvieId != savedRyvieId;
        final unverified = localRyvieId == null;

        if (mismatch) {
          _log.warning(
            '⚠️  ryvie.local répond mais c\'est un AUTRE Ryvie (id=$localRyvieId, attendu=$savedRyvieId) '
            '— bascule directe sur l\'URL publique pour ne pas déconnecter l\'utilisateur',
          );
          return _selectPublicUrlOrThrow();
        }
        if (unverified && hasPublicFallback) {
          // Impossible de confirmer que c'est notre Ryvie (port 3002 ne répond
          // pas dans le délai imparti). C'est suspect : un Ryvie étranger sur le
          // réseau peut très bien répondre sur :3013 sans exposer :3002. Comme
          // on a une URL publique configurée, on préfère la sécurité — bascule
          // sur le tunnel plutôt que de risquer de s'authentifier contre un
          // mauvais Ryvie (ce qui déclencherait un logout côté splash).
          _log.warning(
            '⚠️  ryvie.local répond sur :3013 mais ryvieId non vérifiable sur :3002 '
            '— bascule par précaution sur l\'URL publique pour ne pas risquer un mauvais auth',
          );
          return _selectPublicUrlOrThrow();
        }
        // Si pas de fallback public et ryvieId non vérifié, on continue avec le
        // local : c'est le scénario typique d'une première installation à la
        // maison où on n'a pas encore récupéré les infos tunnel.
      }

      _log.info('✅ Connexion LOCALE réussie - Utilisation de $localServerUrl');

      // Récupérer automatiquement les informations du tunnel en arrière-plan
      // Le token sera récupéré automatiquement du Store dans fetchAndSaveTunnelInfo
      unawaited(
        fetchAndSaveTunnelInfo().catchError((e) {
          _log.warning('Erreur lors de la récupération auto des infos tunnel: $e');
        }),
      );

      return (url: localServerUrl, isLocal: true);
    }

    // 2. Essayer l'URL locale personnalisée (ex: IP saisie à la main quand
    // mDNS/ryvie.local ne résout pas — simulateur, certains routeurs)
    final customLocal = await _trySavedCustomLocalUrl();
    if (customLocal != null) {
      return customLocal;
    }

    // 3. La connexion locale a échoué, essayer l'URL publique
    _log.info('❌ Connexion locale échouée - Tentative connexion PUBLIQUE');
    return _selectPublicUrlOrThrow();
  }

  /// Teste l'URL locale personnalisée mémorisée au login (StoreKey.localEndpoint).
  /// Retourne null si absente, injoignable, ou si le ryvieId ne correspond pas.
  Future<({String url, bool isLocal})?> _trySavedCustomLocalUrl() async {
    final customUrl = Store.tryGet(StoreKey.localEndpoint);
    if (customUrl == null || customUrl.isEmpty || customUrl == localServerUrl) {
      return null;
    }

    _log.info('🔍 Test connexion LOCALE personnalisée: $customUrl');
    final reachable = await _testUrlConnection(customUrl);
    if (!reachable) {
      _log.info('❌ URL locale personnalisée injoignable');
      return null;
    }

    // Pas de rejet sur mismatch de ryvieId ici : cette URL a été saisie
    // explicitement par l'utilisateur au login, elle fait donc autorité.
    // En pratique le ryvieId mémorisé (API cloud Ryvie) peut différer du
    // machine-id exposé sur :3002 pour la même machine, ce qui provoquait
    // un faux "AUTRE Ryvie" et un repli à tort sur le tunnel.
    final savedRyvieId = Store.tryGet(StoreKey.ryvieId);
    if (savedRyvieId != null && savedRyvieId.isNotEmpty) {
      final host = Uri.tryParse(customUrl)?.host;
      if (host != null && host.isNotEmpty) {
        final localRyvieId = await _fetchRyvieIdQuick('http://$host:3002/api/machine-id');
        if (localRyvieId != null && localRyvieId != savedRyvieId) {
          _log.warning(
            '⚠️  ryvieId différent sur $customUrl (id=$localRyvieId, attendu=$savedRyvieId) — '
            'URL saisie manuellement, on continue quand même',
          );
        }
      }
    }

    _log.info('✅ Connexion LOCALE personnalisée réussie - Utilisation de $customUrl');
    unawaited(
      fetchAndSaveTunnelInfo().catchError((e) {
        _log.warning('Erreur lors de la récupération auto des infos tunnel: $e');
      }),
    );
    return (url: customUrl, isLocal: true);
  }

  /// Retourne true si une URL publique ou un tunnelHost est sauvegardé.
  bool _hasPublicUrlConfigured() {
    final publicUrl = Store.tryGet(StoreKey.publicUrl);
    final tunnelHost = Store.tryGet(StoreKey.tunnelHost);
    return (publicUrl != null && publicUrl.isNotEmpty) || (tunnelHost != null && tunnelHost.isNotEmpty);
  }

  /// Retourne l'URL publique/tunnel sauvegardée ou lève NO_TUNNEL_CONFIG.
  /// Utilisé soit en fallback quand le local échoue, soit quand on détecte
  /// que ryvie.local répond pour un AUTRE Ryvie.
  ({String url, bool isLocal}) _selectPublicUrlOrThrow() {
    final publicUrl = Store.tryGet(StoreKey.publicUrl);
    final tunnelHost = Store.tryGet(StoreKey.tunnelHost);

    _log.info('📦 Infos sauvegardées - publicUrl: ${publicUrl ?? "VIDE"}, tunnelHost: ${tunnelHost ?? "VIDE"}');

    String? urlToTry;
    if (publicUrl != null && publicUrl.isNotEmpty) {
      urlToTry = publicUrl;
      _log.info('✅ URL publique trouvée: $urlToTry');
    } else if (tunnelHost != null && tunnelHost.isNotEmpty) {
      urlToTry = 'http://$tunnelHost:3013';
      _log.info('✅ TunnelHost trouvé, construction URL: $urlToTry');
    }

    if (urlToTry != null) {
      _log.info('✅ Utilisation directe de l\'URL PUBLIQUE: $urlToTry');
      return (url: urlToTry, isLocal: false);
    }
    _log.severe('⚠️  Aucune URL publique configurée');
    throw Exception('NO_TUNNEL_CONFIG');
  }

  /// Récupère rapidement le ryvieId du Ryvie qui répond actuellement sur
  /// ryvie.local. Timeout court (2s) — c'est juste pour confirmer qu'on est
  /// bien sur notre Ryvie avant de l'utiliser. Renvoie null en cas d'échec.
  Future<String?> _fetchLocalRyvieIdQuick() => _fetchRyvieIdQuick(localMachineIdUrl);

  /// Variante générique : lit le ryvieId exposé par /api/machine-id à l'URL
  /// donnée (utilisé aussi pour vérifier une IP locale saisie à la main).
  Future<String?> _fetchRyvieIdQuick(String machineIdUrl) async {
    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 2);
      final request = await client
          .getUrl(Uri.parse(machineIdUrl))
          .timeout(const Duration(seconds: 2));
      final response = await request.close().timeout(const Duration(seconds: 2));
      if (response.statusCode == 200) {
        final body = await response.transform(utf8.decoder).join();
        final data = json.decode(body) as Map<String, dynamic>;
        client.close();
        if (data['success'] == true) {
          return data['ryvieId'] as String?;
        }
      } else {
        client.close();
      }
    } catch (e) {
      _log.warning('⚠️  Impossible de lire ryvieId local rapidement: $e');
    }
    return null;
  }

  /// Sauvegarde les informations de tunnel pour une utilisation future
  Future<void> saveTunnelInfo({String? ryvieId, String? tunnelHost, String? publicUrl}) async {
    _log.info('Sauvegarde des informations de tunnel');

    if (ryvieId != null && ryvieId.isNotEmpty) {
      await Store.put(StoreKey.ryvieId, ryvieId);
      _log.info('RyvieId sauvegardé: $ryvieId');
    }

    if (tunnelHost != null && tunnelHost.isNotEmpty) {
      await Store.put(StoreKey.tunnelHost, tunnelHost);
      _log.info('TunnelHost sauvegardé: $tunnelHost');
    }

    if (publicUrl != null && publicUrl.isNotEmpty) {
      await Store.put(StoreKey.publicUrl, publicUrl);
      _log.info('PublicUrl sauvegardée: $publicUrl');
    }
  }

  /// Récupère les informations de tunnel sauvegardées
  ({String? ryvieId, String? tunnelHost, String? publicUrl}) getSavedTunnelInfo() {
    final ryvieId = Store.tryGet(StoreKey.ryvieId);
    final tunnelHost = Store.tryGet(StoreKey.tunnelHost);
    final publicUrl = Store.tryGet(StoreKey.publicUrl);

    return (ryvieId: ryvieId, tunnelHost: tunnelHost, publicUrl: publicUrl);
  }

  /// Efface les informations de tunnel sauvegardées
  Future<void> clearTunnelInfo() async {
    _log.info('Effacement des informations de tunnel');
    await Store.delete(StoreKey.ryvieId);
    await Store.delete(StoreKey.tunnelHost);
    await Store.delete(StoreKey.publicUrl);
  }
}
