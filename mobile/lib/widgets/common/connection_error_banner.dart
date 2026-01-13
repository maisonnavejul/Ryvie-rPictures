import 'package:auto_route/auto_route.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/providers/auth.provider.dart';
import 'package:immich_mobile/providers/connection_status.provider.dart';
import 'package:immich_mobile/providers/server_health_check.provider.dart';
import 'package:immich_mobile/routing/router.dart';
import 'package:logging/logging.dart';

class ConnectionErrorBanner extends HookConsumerWidget {
  const ConnectionErrorBanner({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final log = Logger('ConnectionErrorBanner');
    final connectionState = ref.watch(connectionStatusProvider);
    final previousStatus = usePrevious(connectionState.status);

    log.info('🎨 Banner build - status: ${connectionState.status}');

    // Afficher un dialog quand le statut change vers une erreur
    useEffect(() {
      if (previousStatus != connectionState.status &&
          (connectionState.status == ConnectionStatus.tunnelUnavailable ||
              connectionState.status == ConnectionStatus.noTunnelConfig)) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (context.mounted) {
            _showErrorDialog(context, connectionState, ref);
          }
        });
      }
      return null;
    }, [connectionState.status]);

    // Afficher aussi un banner persistant en haut
    if (connectionState.status == ConnectionStatus.connected ||
        connectionState.status == ConnectionStatus.disconnected) {
      return const SizedBox.shrink();
    }

    String message;
    IconData icon;
    Color backgroundColor;

    switch (connectionState.status) {
      case ConnectionStatus.tunnelUnavailable:
        message = 'Connexion à Ryvie impossible';
        icon = Icons.cloud_off;
        backgroundColor = Colors.orange.shade700;
        break;
      case ConnectionStatus.noTunnelConfig:
        message = 'Configuration requise';
        icon = Icons.info_outline;
        backgroundColor = Colors.blue.shade700;
        break;
      default:
        return const SizedBox.shrink();
    }

    return Material(
      color: backgroundColor,
      elevation: 4,
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        child: SafeArea(
          bottom: false,
          child: Row(
            children: [
              Icon(icon, color: Colors.white, size: 20),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  message,
                  style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                ),
              ),
              TextButton(
                onPressed: () => _showErrorDialog(context, connectionState, ref),
                child: const Text(
                  'Détails',
                  style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
                ),
              ),
              IconButton(
                icon: const Icon(Icons.close, color: Colors.white, size: 20),
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
                onPressed: () {
                  ref.read(connectionStatusProvider.notifier).setDisconnected();
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showErrorDialog(BuildContext context, ConnectionStatusState state, WidgetRef ref) {
    String title;
    IconData icon;
    Color iconColor;

    switch (state.status) {
      case ConnectionStatus.tunnelUnavailable:
        title = 'Connexion impossible';
        icon = Icons.cloud_off_rounded;
        iconColor = Colors.orange;
        break;
      case ConnectionStatus.noTunnelConfig:
        title = 'Configuration requise';
        icon = Icons.info_outline_rounded;
        iconColor = Colors.blue;
        break;
      default:
        return;
    }

    // Vérifier si c'est un problème de RyvieId mismatch
    final healthCheck = ref.read(serverHealthCheckProvider);
    final isRyvieIdMismatch = healthCheck.pendingRyvieId != null;

    showDialog(
      context: context,
      barrierDismissible: !isRyvieIdMismatch, // Ne pas permettre de fermer si c'est un mismatch
      builder: (context) => AlertDialog(
        icon: Icon(
          isRyvieIdMismatch ? Icons.warning_amber_rounded : icon,
          size: 48,
          color: isRyvieIdMismatch ? Colors.red : iconColor,
        ),
        title: Text(
          isRyvieIdMismatch ? 'Ryvie différent détecté' : title,
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                isRyvieIdMismatch
                    ? 'Vous tentez de vous connecter à un Ryvie différent de celui configuré actuellement.'
                    : (state.errorMessage ?? 'Une erreur est survenue'),
                style: const TextStyle(fontSize: 15, height: 1.4),
              ),
              if (isRyvieIdMismatch) ...[
                const SizedBox(height: 20),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.orange.shade50,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.orange.shade300, width: 1.5),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.info_outline, color: Colors.orange.shade700, size: 24),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          'Vos données locales seront conservées mais liées à ce nouveau serveur.',
                          style: TextStyle(fontSize: 13, color: Colors.orange.shade900, height: 1.3),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
        actions: isRyvieIdMismatch
            ? [
                // Boutons côte à côte
                Expanded(
                  child: OutlinedButton(
                    onPressed: () async {
                      Navigator.of(context).pop();
                      healthCheck.rejectNewRyvieId();
                      // Basculer vers la connexion tunnel au lieu de déconnecter
                      try {
                        final tunnelUrl = await ref
                            .read(authProvider.notifier)
                            .setOpenApiServiceEndpoint(forceTunnel: true);
                        if (tunnelUrl != null) {
                          ref.read(connectionStatusProvider.notifier).setConnected(tunnelUrl);
                        }
                      } catch (e) {
                        // Si la connexion tunnel échoue, afficher une erreur
                        ref
                            .read(connectionStatusProvider.notifier)
                            .setTunnelUnavailable(
                              'Impossible de se connecter via le tunnel.\n\nVeuillez vérifier votre configuration.',
                            );
                      }
                    },
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Colors.red,
                      side: BorderSide(color: Colors.red.shade300),
                      padding: const EdgeInsets.symmetric(vertical: 12),
                    ),
                    child: const Text('Non', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: () async {
                      // Sauvegarder le context avant de fermer le dialogue
                      final navigator = Navigator.of(context);
                      final router = context.router;

                      navigator.pop();
                      healthCheck.rejectNewRyvieId();
                      // Déconnecter l'utilisateur pour qu'il puisse reconfigurer
                      await ref.read(authProvider.notifier).logout();

                      // Rediriger vers la page de login
                      await router.replaceAll([const LoginRoute()]);
                    },
                    style: FilledButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 12)),
                    child: const Text('Oui', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                  ),
                ),
              ]
            : [
                TextButton(
                  onPressed: () {
                    Navigator.of(context).pop();
                    ref.read(connectionStatusProvider.notifier).setDisconnected();
                  },
                  child: const Text('OK'),
                ),
              ],
      ),
    );
  }
}
