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
  static const String localApiUrl = 'http://ryvie.local:3002/api/settings/ryvie-domains';
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
  Future<void> fetchAndSaveTunnelInfo() async {
    try {
      _log.info('🔄 Récupération automatique des informations du tunnel...');

      final uri = Uri.parse(localApiUrl);
      final client = HttpClient();
      client.connectionTimeout = connectionTimeout;

      final request = await client.getUrl(uri);
      final response = await request.close();

      if (response.statusCode == 200) {
        final responseBody = await response.transform(utf8.decoder).join();
        final data = json.decode(responseBody) as Map<String, dynamic>;

        if (data['success'] == true) {
          final tunnelHost = data['tunnelHost'] as String?;
          final publicUrl = data['publicUrl'] as String?;

          // Ne sauvegarder que tunnelHost et publicUrl, PAS le ryvieId
          // Le ryvieId sera vérifié et sauvegardé par le ServerHealthCheck
          await saveTunnelInfo(tunnelHost: tunnelHost, publicUrl: publicUrl);

          _log.info(
            '✅ Informations du tunnel récupérées et sauvegardées automatiquement (tunnelHost: ${tunnelHost ?? "N/A"})',
          );
        } else {
          _log.warning('⚠️  API retourne success=false');
        }
      } else {
        _log.warning('⚠️  Échec récupération infos tunnel: HTTP ${response.statusCode}');
      }

      client.close();
    } catch (e) {
      _log.warning('⚠️  Erreur lors de la récupération des infos tunnel: $e');
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
      _log.info('✅ Connexion LOCALE réussie - Utilisation de $localServerUrl');

      // Récupérer automatiquement les informations du tunnel en arrière-plan
      fetchAndSaveTunnelInfo().catchError((e) {
        _log.warning('Erreur lors de la récupération auto des infos tunnel: $e');
      });

      return (url: localServerUrl, isLocal: true);
    }

    // 2. La connexion locale a échoué, essayer l'URL publique
    _log.info('❌ Connexion locale échouée - Tentative connexion PUBLIQUE');

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
      // Pour l'URL publique/tunnel, on ne fait plus de test HTTP préalable.
      // On se comporte comme lorsque l'utilisateur saisit l'URL à la main :
      // on utilise directement cette URL, et les appels API remonteront
      // une erreur s'il y a réellement un problème.
      _log.info('✅ Utilisation directe de l\'URL PUBLIQUE: $urlToTry');
      return (url: urlToTry, isLocal: false);
    } else {
      _log.severe('⚠️  Aucune URL publique configurée');
      throw Exception('NO_TUNNEL_CONFIG');
    }
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
