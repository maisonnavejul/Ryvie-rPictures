import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/providers/auth.provider.dart';
import 'package:immich_mobile/providers/connection_status.provider.dart';
import 'package:logging/logging.dart';

final serverHealthCheckProvider = Provider<ServerHealthCheckNotifier>((ref) {
  return ServerHealthCheckNotifier(ref);
});

class ServerHealthCheckNotifier {
  final Ref _ref;
  final _log = Logger('ServerHealthCheck');
  bool _isChecking = false;
  Timer? _retryTimer;
  bool _errorAlreadyShown = false;

  ServerHealthCheckNotifier(this._ref);

  /// Lance un health check unique (au démarrage de l'app)
  /// Vérifie aussi le ryvieId pour les connexions locales
  Future<void> performHealthCheck() async {
    _log.info('🏥 Lancement du health check au démarrage');

    final serverUrl = Store.tryGet(StoreKey.serverUrl);
    if (serverUrl == null || serverUrl.isEmpty) {
      _log.warning('⚠️  Pas d\'URL serveur configurée');
      return;
    }

    // Si c'est une connexion locale, vérifier le ryvieId
    final isLocalConnection = serverUrl.contains('ryvie.local');
    if (isLocalConnection) {
      _log.info('🔍 Connexion locale détectée, vérification du ryvieId...');
      final savedRyvieId = Store.tryGet(StoreKey.ryvieId);
      _log.info('📦 RyvieId sauvegardé: ${savedRyvieId ?? "AUCUN"}');

      try {
        await _checkLocalConnectionWithRyvieId(serverUrl);
        _log.info('✅ RyvieId validé pour connexion locale');
      } catch (e) {
        _log.severe('❌ Erreur lors de la validation du ryvieId', e);
        // Si le ryvieId ne correspond pas, basculer automatiquement sur le tunnel
        if (e.toString().contains('RYVIE_ID_MISMATCH:')) {
          final newRyvieId = e.toString().split('RYVIE_ID_MISMATCH:')[1];
          _log.warning('⚠️  RyvieId différent détecté: $newRyvieId (attendu: $savedRyvieId)');
          _log.info('🔄 Basculement automatique vers le tunnel...');

          // Basculer vers le tunnel automatiquement
          try {
            final authNotifier = _ref.read(authProvider.notifier);
            final tunnelUrl = await authNotifier.setOpenApiServiceEndpoint(forceTunnel: true);

            if (tunnelUrl != null) {
              _log.info('✅ Basculement réussi vers le tunnel: $tunnelUrl');
              _ref.read(connectionStatusProvider.notifier).setConnected(tunnelUrl);
              return; // Health check terminé avec succès via tunnel
            } else {
              _log.severe('❌ Impossible de basculer vers le tunnel (pas d\'URL configurée)');
              _ref
                  .read(connectionStatusProvider.notifier)
                  .setTunnelUnavailable(
                    'Impossible de se connecter.\n\n'
                    'Vous êtes sur un réseau avec un autre Ryvie et aucun tunnel n\'est configuré.',
                  );
              return;
            }
          } catch (tunnelError) {
            _log.severe('❌ Erreur lors du basculement vers le tunnel', tunnelError);
            _ref
                .read(connectionStatusProvider.notifier)
                .setTunnelUnavailable(
                  'Impossible de se connecter via le tunnel.\n\n'
                  'Vérifiez votre connexion Internet.',
                );
            return;
          }
        }
      }
    }

    // Ensuite faire le health check normal
    await checkServerHealth();
  }

  /// Démarre les tentatives de reconnexion périodiques (toutes les 5 secondes)
  void startRetryLoop() {
    if (_retryTimer != null && _retryTimer!.isActive) {
      _log.info('⏭️  Retry loop déjà actif');
      return;
    }

    _log.info('🔄 Démarrage du retry loop (toutes les 5 secondes)');
    _retryTimer = Timer.periodic(const Duration(seconds: 5), (_) => checkServerHealth());
  }

  /// Arrête les tentatives de reconnexion
  void stopRetryLoop() {
    if (_retryTimer != null) {
      _log.info('🛑 Arrêt du retry loop');
      _retryTimer?.cancel();
      _retryTimer = null;
    }
  }

  /// Vérifie la santé du serveur avec un timeout de 5 secondes
  Future<void> checkServerHealth() async {
    if (_isChecking) {
      _log.info('⏭️  Health check déjà en cours, skip');
      return;
    }

    _isChecking = true;
    _log.info('🔍 Health check du serveur...');

    try {
      final serverUrl = Store.tryGet(StoreKey.serverUrl);

      if (serverUrl == null || serverUrl.isEmpty) {
        _log.warning('⚠️  Pas d\'URL serveur configurée');
        _isChecking = false;
        return;
      }

      _log.info('🌐 Test de connexion à: $serverUrl');

      // Pour toutes les connexions, faire un simple test HTTP
      await _checkRemoteConnection(serverUrl);

      // Arrêter le retry loop si actif
      stopRetryLoop();

      // Réinitialiser le flag d'erreur pour la prochaine fois
      _errorAlreadyShown = false;

      // Marquer comme connecté
      _ref.read(connectionStatusProvider.notifier).setConnected(serverUrl);

      // Actualiser la page principale (invalider les providers pour forcer le refresh)
      _log.info('🔄 Actualisation de la page principale après reconnexion');
      _ref.invalidate(connectionStatusProvider);
    } on TimeoutException catch (e) {
      _log.severe('❌ Timeout du health check', e);

      // N'afficher le message d'erreur qu'une seule fois
      if (!_errorAlreadyShown) {
        _log.info('🔴 Affichage du message d\'erreur (première fois)');
        _ref
            .read(connectionStatusProvider.notifier)
            .setTunnelUnavailable(
              'Impossible de se connecter à votre Ryvie.\n\n'
              'Vérifiez que :\n'
              '• Votre téléphone a accès à Internet\n'
              '• L\'application Ryvie Connect est ouverte sur votre téléphone principal\n\n'
              'Si vous êtes chez vous, reconnectez-vous au WiFi.',
            );
        _errorAlreadyShown = true;
      } else {
        _log.info('⏭️  Erreur détectée mais message déjà affiché, skip');
      }

      // Démarrer le retry loop pour tenter de se reconnecter
      startRetryLoop();
    } on SocketException catch (e) {
      _log.severe('❌ Erreur réseau lors du health check', e);

      // N'afficher le message d'erreur qu'une seule fois
      if (!_errorAlreadyShown) {
        _log.info('🔴 Affichage du message d\'erreur (première fois)');
        _ref
            .read(connectionStatusProvider.notifier)
            .setTunnelUnavailable(
              'Impossible de se connecter à votre Ryvie.\n\n'
              'Vérifiez que :\n'
              '• Votre téléphone a accès à Internet\n'
              '• L\'application Ryvie Connect est ouverte sur votre téléphone principal\n\n'
              'Si vous êtes chez vous, reconnectez-vous au WiFi.',
            );
        _errorAlreadyShown = true;
      } else {
        _log.info('⏭️  Erreur détectée mais message déjà affiché, skip');
      }

      // Démarrer le retry loop pour tenter de se reconnecter
      startRetryLoop();
    } catch (e, stackTrace) {
      _log.severe('❌ Erreur inattendue lors du health check', e, stackTrace);

      // Vérifier si c'est une erreur de RyvieId mismatch
      final isRyvieIdMismatch = e.toString().contains('RYVIE_ID_MISMATCH');

      // N'afficher le message d'erreur qu'une seule fois
      if (!_errorAlreadyShown) {
        _log.info('🔴 Affichage du message d\'erreur (première fois)');

        if (isRyvieIdMismatch) {
          // Message spécifique pour RyvieId différent
          _ref
              .read(connectionStatusProvider.notifier)
              .setTunnelUnavailable(
                '⚠️  Ryvie différent détecté !\n\n'
                'L\'application est configurée pour un autre Ryvie.\n\n'
                'Si vous avez changé de Ryvie, veuillez vous déconnecter et vous reconnecter.',
              );
        } else {
          // Message générique pour les autres erreurs
          _ref
              .read(connectionStatusProvider.notifier)
              .setTunnelUnavailable(
                'Impossible de se connecter à votre Ryvie.\n\n'
                'Vérifiez que :\n'
                '• Votre téléphone a accès à Internet\n'
                '• L\'application Ryvie Connect est ouverte sur votre téléphone principal\n\n'
                'Si vous êtes chez vous, reconnectez-vous au WiFi.',
              );
        }
        _errorAlreadyShown = true;
      } else {
        _log.info('⏭️  Erreur détectée mais message déjà affiché, skip');
      }

      // Ne pas démarrer le retry loop si c'est un problème de RyvieId mismatch
      if (!isRyvieIdMismatch) {
        startRetryLoop();
      }
    } finally {
      _isChecking = false;
    }
  }

  /// Vérifie la connexion locale avec validation du ryvieId
  Future<void> _checkLocalConnectionWithRyvieId(String serverUrl) async {
    _log.info('🏠 Vérification connexion LOCALE avec validation ryvieId');

    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 5);

    // Utiliser l'endpoint Ryvie Settings sur le port 3002
    // Endpoint léger qui renvoie juste { success, ryvieId } sans nécessiter
    // de JWT — parfait pour le health-check.
    const apiUrl = 'http://ryvie.local:3002/api/machine-id';
    final uri = Uri.parse(apiUrl);

    _log.info('🔗 Appel API: $apiUrl');

    final request = await client
        .getUrl(uri)
        .timeout(
          const Duration(seconds: 5),
          onTimeout: () {
            _log.severe('❌ Timeout lors de la récupération du ryvieId');
            throw TimeoutException('RyvieId fetch timeout');
          },
        );

    final response = await request.close().timeout(
      const Duration(seconds: 5),
      onTimeout: () {
        _log.severe('❌ Timeout lors de la réponse ryvieId');
        throw TimeoutException('RyvieId response timeout');
      },
    );

    if (response.statusCode == 200) {
      final responseBody = await response.transform(utf8.decoder).join();
      final data = json.decode(responseBody) as Map<String, dynamic>;

      if (data['success'] == true) {
        final currentRyvieId = data['ryvieId'] as String?;
        final savedRyvieId = Store.tryGet(StoreKey.ryvieId);

        _log.info('🔍 RyvieId actuel: ${currentRyvieId ?? "N/A"}');
        _log.info('🔍 RyvieId sauvegardé: ${savedRyvieId ?? "N/A"}');

        // Si un ryvieId est sauvegardé, vérifier qu'il correspond AVANT de sauvegarder
        if (savedRyvieId != null && savedRyvieId.isNotEmpty) {
          if (currentRyvieId != null && currentRyvieId != savedRyvieId) {
            _log.severe('⚠️  RyvieId différent détecté!');
            _log.severe('   Attendu: $savedRyvieId');
            _log.severe('   Reçu: $currentRyvieId');
            _log.severe('   ⚠️  L\'utilisateur doit confirmer le changement de Ryvie');
            throw Exception('RYVIE_ID_MISMATCH:$currentRyvieId');
          }
          _log.info('✅ RyvieId correspond: $currentRyvieId');
        } else {
          // Première connexion, sauvegarder le ryvieId automatiquement
          if (currentRyvieId != null && currentRyvieId.isNotEmpty) {
            await Store.put(StoreKey.ryvieId, currentRyvieId);
            _log.info('✅ Premier RyvieId sauvegardé: $currentRyvieId');
          }
        }

        _log.info('✅ Connexion locale validée avec ryvieId correct');
      } else {
        throw Exception('API returned success=false');
      }
    } else {
      throw Exception('HTTP ${response.statusCode}');
    }

    client.close();
  }

  /// Vérifie la connexion distante (tunnel/publique) sans validation ryvieId
  Future<void> _checkRemoteConnection(String serverUrl) async {
    _log.info('🌐 Vérification connexion DISTANTE (simple HTTP)');

    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 5);

    final uri = Uri.parse(serverUrl);
    final request = await client
        .getUrl(uri)
        .timeout(
          const Duration(seconds: 5),
          onTimeout: () {
            _log.severe('❌ Timeout lors du health check distant');
            throw TimeoutException('Remote health check timeout');
          },
        );

    final response = await request.close().timeout(
      const Duration(seconds: 5),
      onTimeout: () {
        _log.severe('❌ Timeout lors de la réponse distante');
        throw TimeoutException('Remote response timeout');
      },
    );

    client.close();

    _log.info('✅ Serveur distant accessible (HTTP ${response.statusCode})');
  }
}
