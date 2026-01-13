import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/extensions/build_context_extensions.dart';
import 'package:logging/logging.dart';

/// Dialogue affiché quand un changement de Ryvie est détecté
/// Demande à l'utilisateur s'il veut accepter le nouveau Ryvie ou se déconnecter
class RyvieIdMismatchDialog extends StatelessWidget {
  final String newRyvieId;
  final VoidCallback onAccept;
  final VoidCallback onReject;

  const RyvieIdMismatchDialog({super.key, required this.newRyvieId, required this.onAccept, required this.onReject});

  static final _log = Logger('RyvieIdMismatchDialog');

  /// Affiche le dialogue et retourne true si l'utilisateur accepte, false sinon
  static Future<bool> show(BuildContext context, String newRyvieId) async {
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => RyvieIdMismatchDialog(
        newRyvieId: newRyvieId,
        onAccept: () => Navigator.of(context).pop(true),
        onReject: () => Navigator.of(context).pop(false),
      ),
    );

    return result ?? false;
  }

  /// Sauvegarde le nouveau ryvieId après confirmation de l'utilisateur
  static Future<void> acceptNewRyvieId(String newRyvieId) async {
    _log.info('✅ Utilisateur a accepté le nouveau RyvieId: $newRyvieId');
    await Store.put(StoreKey.ryvieId, newRyvieId);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Row(
        children: [
          Icon(Icons.warning_amber_rounded, color: context.colorScheme.error, size: 28),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              'ryvie_id_mismatch_title'.tr(),
              style: context.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('ryvie_id_mismatch_message'.tr(), style: context.textTheme.bodyMedium),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: context.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'ryvie_id_mismatch_details'.tr(),
                  style: context.textTheme.bodySmall?.copyWith(fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                Text(
                  'ryvie_id_mismatch_warning'.tr(),
                  style: context.textTheme.bodySmall?.copyWith(color: context.colorScheme.error),
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: onReject,
          child: Text('ryvie_id_mismatch_logout'.tr(), style: TextStyle(color: context.colorScheme.error)),
        ),
        FilledButton(onPressed: onAccept, child: Text('ryvie_id_mismatch_accept'.tr())),
      ],
    );
  }
}
