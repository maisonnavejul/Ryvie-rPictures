import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/providers/connection_status.provider.dart';
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

    showDialog(
      context: context,
      barrierDismissible: true,
      builder: (context) => AlertDialog(
        icon: Icon(icon, size: 48, color: iconColor),
        title: Text(
          title,
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
        ),
        content: SingleChildScrollView(
          child: Text(
            state.errorMessage ?? 'Une erreur est survenue',
            style: const TextStyle(fontSize: 15, height: 1.4),
          ),
        ),
        actions: [
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
