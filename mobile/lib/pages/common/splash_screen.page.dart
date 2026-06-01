import 'dart:async';

import 'package:auto_route/auto_route.dart';
import 'package:flutter/material.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/providers/auth.provider.dart';
import 'package:immich_mobile/providers/background_sync.provider.dart';
import 'package:immich_mobile/providers/backup/backup.provider.dart';
import 'package:immich_mobile/providers/backup/drift_backup.provider.dart';
import 'package:immich_mobile/providers/connection_status.provider.dart';
import 'package:immich_mobile/providers/gallery_permission.provider.dart';
import 'package:immich_mobile/providers/server_info.provider.dart';
import 'package:immich_mobile/providers/websocket.provider.dart';
import 'package:immich_mobile/routing/router.dart';
import 'package:logging/logging.dart';

@RoutePage()
class SplashScreenPage extends StatefulHookConsumerWidget {
  const SplashScreenPage({super.key});

  @override
  SplashScreenPageState createState() => SplashScreenPageState();
}

class SplashScreenPageState extends ConsumerState<SplashScreenPage> {
  final log = Logger("SplashScreenPage");

  @override
  void initState() {
    super.initState();
    ref
        .read(authProvider.notifier)
        .setOpenApiServiceEndpoint()
        .then(logConnectionInfo)
        .catchError((error, stackTrace) {
          log.severe('❌ Erreur lors du switch d\'endpoint au démarrage', error, stackTrace);

          final errorStr = error.toString();
          if (errorStr.contains('NO_TUNNEL_CONFIG')) {
            log.info('🔵 Affichage message NO_TUNNEL_CONFIG (SplashScreen)');
            ref
                .read(connectionStatusProvider.notifier)
                .setNoTunnelConfig(
                  'Pour accéder à votre Ryvie depuis l\'extérieur :\n\n'
                  '1. Connectez-vous au WiFi de votre domicile\n'
                  '2. Ouvrez rPictures\n'
                  '3. Installez l\'application Ryvie Connect sur votre téléphone principal',
                );
          }
        })
        .whenComplete(() => resumeSession());
  }

  void logConnectionInfo(String? endpoint) {
    if (endpoint == null) {
      return;
    }

    log.info("Resuming session at $endpoint");
  }

  void resumeSession() async {
    final serverUrl = Store.tryGet(StoreKey.serverUrl);
    final endpoint = Store.tryGet(StoreKey.serverEndpoint);
    final accessToken = Store.tryGet(StoreKey.accessToken);

    if (accessToken != null && serverUrl != null && endpoint != null) {
      final infoProvider = ref.read(serverInfoProvider.notifier);
      final wsProvider = ref.read(websocketProvider.notifier);
      final backgroundManager = ref.read(backgroundSyncProvider);
      final backupProvider = ref.read(driftBackupProvider.notifier);

      unawaited(
        ref.read(authProvider.notifier).saveAuthInfo(accessToken: accessToken).then(
          (_) async {
            try {
              wsProvider.connect();
              unawaited(infoProvider.getServerInfo());

              if (Store.isBetaTimelineEnabled) {
                bool syncSuccess = false;
                await Future.wait([
                  backgroundManager.syncLocal(full: true),
                  backgroundManager.syncRemote().then((success) => syncSuccess = success),
                ]);

                if (syncSuccess) {
                  await Future.wait([
                    backgroundManager.hashAssets().then((_) {
                      _resumeBackup(backupProvider);
                    }),
                    _resumeBackup(backupProvider),
                  ]);
                } else {
                  await backgroundManager.hashAssets();
                }

                if (Store.get(StoreKey.syncAlbums, false)) {
                  await backgroundManager.syncLinkedAlbum();
                }
              }
            } catch (e) {
              log.severe('Failed establishing connection to the server: $e');
            }
          },
          onError: (exception) async {
            log.severe('Failed to update auth info with access token: $accessToken — $exception');

            // On est peut-être sur un réseau étranger où ryvie.local pointe
            // vers un autre Ryvie. On essaye de basculer sur l'URL publique
            // et de re-tenter l'auth.
            try {
              final tunnelUrl = await ref
                  .read(authProvider.notifier)
                  .setOpenApiServiceEndpoint(forceTunnel: true);
              if (tunnelUrl != null) {
                log.info('🔄 Bascule sur tunnel après échec auth: $tunnelUrl — re-tentative');
                final retryOk = await ref
                    .read(authProvider.notifier)
                    .saveAuthInfo(accessToken: accessToken)
                    .then((_) => true, onError: (_) => false);
                if (retryOk) {
                  log.info('✅ Auth réussie via tunnel après échec local');
                  return;
                }
                log.warning('⚠️  Auth via tunnel échouée aussi — on reste connecté quand même');
              }
            } catch (tunnelError) {
              log.warning('⚠️  Impossible de basculer sur tunnel: $tunnelError');
            }

            // Pas de déconnexion automatique — l'utilisateur peut être hors
            // ligne ou sur un réseau qui n'a pas accès. On laisse la session
            // intacte ; le health-check / banner se chargera d'indiquer
            // l'état réseau et de retenter en arrière-plan.
            log.info('ℹ️  Auth échouée mais on garde la session (pas de déconnexion auto)');
          },
        ),
      );
    } else {
      // Vraie absence de credentials (accessToken / serverUrl / endpoint manquants) —
      // l'utilisateur n'est jamais loggé OU les données ont été effacées manuellement.
      // On ne fait PAS de logout (rien à logout) ; on route juste vers l'écran de
      // connexion. Aucune déconnexion automatique de session valide possible.
      log.info('ℹ️  Aucun credential trouvé — route vers Login (pas de logout)');
      unawaited(context.replaceRoute(const LoginRoute()));
      return;
    }

    // clean install - change the default of the flag
    // current install not using beta timeline
    if (context.router.current.name == SplashScreenRoute.name) {
      final needBetaMigration = Store.get(StoreKey.needBetaMigration, false);
      if (needBetaMigration) {
        await Store.put(StoreKey.needBetaMigration, false);
        unawaited(context.router.replaceAll([ChangeExperienceRoute(switchingToBeta: true)]));
        return;
      }

      unawaited(context.replaceRoute(Store.isBetaTimelineEnabled ? const TabShellRoute() : const TabControllerRoute()));
    }

    if (Store.isBetaTimelineEnabled) {
      return;
    }

    final hasPermission = await ref.read(galleryPermissionNotifier.notifier).hasPermission;
    if (hasPermission) {
      // Resume backup (if enable) then navigate
      await ref.watch(backupProvider.notifier).resumeBackup();
    }
  }

  Future<void> _resumeBackup(DriftBackupNotifier notifier) async {
    final isEnableBackup = Store.get(StoreKey.enableBackup, false);

    if (isEnableBackup) {
      final currentUser = Store.tryGet(StoreKey.currentUser);
      if (currentUser != null) {
        unawaited(notifier.handleBackupResume(currentUser.id));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Image(image: AssetImage('assets/rpictures-logo.png'), width: 80, filterQuality: FilterQuality.high),
      ),
    );
  }
}
