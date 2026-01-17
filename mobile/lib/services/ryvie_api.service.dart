import 'dart:convert';
import 'dart:io';
import 'package:logging/logging.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';

/// Service pour communiquer avec l'API Ryvie (port 3002)
/// Gère l'authentification et la récupération des informations tunnel
class RyvieApiService {
  final _log = Logger('RyvieApiService');

  static const String localRyvieApiUrl = 'http://ryvie.local:3002';
  static const Duration connectionTimeout = Duration(seconds: 5);

  /// Authentifie l'utilisateur sur l'API Ryvie et retourne le token JWT
  /// Utilise les mêmes credentials que rPictures (uid/password)
  Future<String?> authenticate({required String uid, required String password}) async {
    try {
      _log.info('🔐 Authentification sur l\'API Ryvie...');
      _log.info('   URL: $localRyvieApiUrl/api/authenticate');
      _log.info('   UID: $uid');

      final uri = Uri.parse('$localRyvieApiUrl/api/authenticate');
      final client = HttpClient();
      client.connectionTimeout = connectionTimeout;

      final request = await client.postUrl(uri);

      // Définir les headers
      request.headers.set('Content-Type', 'application/json');

      // Préparer le body JSON
      final body = json.encode({'uid': uid, 'password': password});

      _log.info('📤 Envoi de la requête d\'authentification...');
      request.write(body);

      final response = await request.close();
      final responseBody = await response.transform(utf8.decoder).join();

      _log.info('📥 Réponse reçue - Status: ${response.statusCode}');
      _log.info('📦 Body: $responseBody');

      if (response.statusCode == 200) {
        final data = json.decode(responseBody) as Map<String, dynamic>;

        // La réponse contient directement le token, pas de champ "success"
        final token = data['token'] as String?;

        if (token != null && token.isNotEmpty) {
          _log.info('✅ Authentification Ryvie réussie !');
          _log.info('🔑 Token JWT Ryvie reçu - longueur: ${token.length} caractères');
          _log.info('👤 User: ${data['user']?['name'] ?? "N/A"}');
          _log.info('📧 Email: ${data['user']?['email'] ?? "N/A"}');
          return token;
        } else {
          _log.severe('❌ Token manquant dans la réponse');
          return null;
        }
      } else if (response.statusCode == 400) {
        _log.severe('❌ Erreur 400 - UID et mot de passe requis');
        return null;
      } else if (response.statusCode == 401) {
        _log.severe('❌ Erreur 401 - Identifiant ou mot de passe incorrect');
        final data = json.decode(responseBody) as Map<String, dynamic>;
        final attempts = data['attempts'];
        if (attempts != null) {
          _log.severe('   Tentatives: $attempts/5');
        }
        return null;
      } else if (response.statusCode == 429) {
        _log.severe('❌ Erreur 429 - Trop de tentatives. Réessayez dans 15 minutes.');
        return null;
      } else {
        _log.severe('❌ Erreur HTTP ${response.statusCode}');
        _log.severe('   Réponse: $responseBody');
        return null;
      }
    } catch (e, stackTrace) {
      _log.severe('❌ Erreur lors de l\'authentification Ryvie: $e');
      _log.severe('   Stack trace: $stackTrace');
      return null;
    }
  }

  /// Récupère les informations du tunnel en utilisant le token JWT Ryvie
  Future<({String? ryvieId, String? tunnelHost, String? publicUrl, String? setupKey})> fetchTunnelInfo({
    required String ryvieToken,
  }) async {
    try {
      _log.info('🔄 Récupération des informations du tunnel avec token Ryvie...');

      final uri = Uri.parse('$localRyvieApiUrl/api/settings/ryvie-domains');
      final client = HttpClient();
      client.connectionTimeout = connectionTimeout;

      final request = await client.getUrl(uri);

      // Ajouter le header Authorization avec le token JWT RYVIE
      request.headers.set('Authorization', 'Bearer $ryvieToken');
      _log.info('📤 Envoi requête à: $localRyvieApiUrl/api/settings/ryvie-domains');
      _log.info('🔑 Avec token Ryvie JWT - longueur: ${ryvieToken.length} caractères');

      final response = await request.close();
      final responseBody = await response.transform(utf8.decoder).join();

      _log.info('📥 Réponse reçue - Status: ${response.statusCode}');
      _log.info('📦 Body de la réponse: $responseBody');

      if (response.statusCode == 200) {
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

          return (ryvieId: ryvieId, tunnelHost: tunnelHost, publicUrl: publicUrl, setupKey: setupKey);
        } else {
          _log.warning('⚠️  API retourne success=false');
          _log.warning('   Réponse complète: $responseBody');
        }
      } else if (response.statusCode == 401) {
        _log.severe('❌ Erreur 401 Unauthorized - Token JWT Ryvie invalide ou expiré');
      } else if (response.statusCode == 403) {
        _log.severe('❌ Erreur 403 Forbidden - Accès refusé');
      } else {
        _log.warning('⚠️  Échec récupération infos tunnel: HTTP ${response.statusCode}');
        _log.warning('   Réponse: $responseBody');
      }

      client.close();
    } catch (e, stackTrace) {
      _log.warning('⚠️  Erreur lors de la récupération des infos tunnel: $e');
      _log.warning('   Stack trace: $stackTrace');
    }

    return (ryvieId: null, tunnelHost: null, publicUrl: null, setupKey: null);
  }

  /// Authentifie et récupère les infos tunnel en une seule opération
  Future<({String? ryvieId, String? tunnelHost, String? publicUrl, String? setupKey})> authenticateAndFetchTunnelInfo({
    required String uid,
    required String password,
  }) async {
    _log.info('🚀 Démarrage authentification Ryvie + récupération infos tunnel');

    // Étape 1 : Authentification sur l'API Ryvie
    final ryvieToken = await authenticate(uid: uid, password: password);

    if (ryvieToken == null) {
      _log.severe('❌ Impossible de récupérer le token Ryvie - abandon');
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

  /// Sauvegarde les informations de tunnel dans le Store
  Future<void> _saveTunnelInfo({String? ryvieId, String? tunnelHost, String? publicUrl}) async {
    _log.info('💾 Sauvegarde des informations de tunnel');

    if (ryvieId != null && ryvieId.isNotEmpty) {
      await Store.put(StoreKey.ryvieId, ryvieId);
      _log.info('   ✅ RyvieId sauvegardé: $ryvieId');
    }

    if (tunnelHost != null && tunnelHost.isNotEmpty) {
      await Store.put(StoreKey.tunnelHost, tunnelHost);
      _log.info('   ✅ TunnelHost sauvegardé: $tunnelHost');
    }

    if (publicUrl != null && publicUrl.isNotEmpty) {
      await Store.put(StoreKey.publicUrl, publicUrl);
      _log.info('   ✅ PublicUrl sauvegardée: $publicUrl');
    }
  }
}
