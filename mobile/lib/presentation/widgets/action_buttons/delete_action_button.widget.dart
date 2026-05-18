import 'package:flutter/material.dart';
import 'package:fluttertoast/fluttertoast.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/constants/enums.dart';
import 'package:immich_mobile/domain/utils/event_stream.dart';
import 'package:immich_mobile/extensions/build_context_extensions.dart';
import 'package:immich_mobile/extensions/translate_extensions.dart';
import 'package:immich_mobile/presentation/widgets/action_buttons/base_action_button.widget.dart';
import 'package:immich_mobile/presentation/widgets/asset_viewer/asset_viewer.state.dart';
import 'package:immich_mobile/providers/infrastructure/action.provider.dart';
import 'package:immich_mobile/providers/timeline/multiselect.provider.dart';
import 'package:immich_mobile/widgets/asset_grid/delete_dialog.dart';
import 'package:immich_mobile/widgets/common/immich_toast.dart';

/// This delete action has the following behavior:
/// - Set the deletedAt information, put the asset in the trash in the server
/// which will be permanently deleted after the number of days configure by the admin
/// - Prompt to delete the asset locally
class DeleteActionButton extends ConsumerWidget {
  final ActionSource source;
  final bool showConfirmation;
  const DeleteActionButton({super.key, required this.source, this.showConfirmation = false});

  void _onTap(BuildContext context, WidgetRef ref) async {
    if (!context.mounted) {
      return;
    }

    // En multi-sélection, on regarde si la sélection contient des photos
    // locales (locales-pures OU mergées) pour proposer un prompt cohérent
    // avec le comportement single-photo : "Que faire des fichiers locaux ?".
    final multiselect = ref.read(multiSelectProvider);
    final isMultiSelect = source == ActionSource.timeline;
    final hasLocalContent = multiselect.hasLocal || multiselect.hasMerged;

    if (isMultiSelect && hasLocalContent) {
      // Reproduit le prompt du single-photo (DeleteLocalOnlyDialog) :
      //  - Annuler
      //  - Supprimer du serveur + supprimer en local SEULEMENT les sauvegardées
      //    (les local-only restent intactes)
      //  - Tout supprimer (force) : serveur + local, y compris local-only
      final choice = await showDialog<bool>(
        context: context,
        builder: (context) => DeleteLocalOnlyDialog(onDeleteLocal: (_) {}),
      );
      if (choice == null) return; // annulé
      if (choice) {
        // Sauvegardées seulement : trash remote + supprime local des mergées,
        // laisse les local-only tranquilles.
        final result = await ref.read(actionProvider.notifier).trashRemoteAndDeleteLocalBackedUpOnly(source);
        ref.read(multiSelectProvider.notifier).reset();
        if (context.mounted) {
          ImmichToast.show(
            context: context,
            msg: result.success
                ? 'delete_action_prompt'.t(context: context, args: {'count': result.count.toString()})
                : 'scaffold_body_error_occurred'.t(context: context),
            gravity: ToastGravity.BOTTOM,
            toastType: result.success ? ToastType.success : ToastType.error,
          );
        }
        return;
      }
      // choice == false → force delete : on tombe sur le flux normal qui
      // supprime tout (server + local).
    } else if (showConfirmation) {
      final confirm = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text('delete'.t(context: context)),
          content: Text('delete_action_confirmation_message'.t(context: context)),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: Text('cancel'.t(context: context)),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: Text(
                'confirm'.t(context: context),
                style: TextStyle(color: context.colorScheme.error),
              ),
            ),
          ],
        ),
      );
      if (confirm != true) return;
    }

    final result = await ref.read(actionProvider.notifier).trashRemoteAndDeleteLocal(source);
    ref.read(multiSelectProvider.notifier).reset();

    if (source == ActionSource.viewer) {
      EventStream.shared.emit(const ViewerReloadAssetEvent());
    }

    final successMessage = 'delete_action_prompt'.t(context: context, args: {'count': result.count.toString()});

    if (context.mounted) {
      ImmichToast.show(
        context: context,
        msg: result.success ? successMessage : 'scaffold_body_error_occurred'.t(context: context),
        gravity: ToastGravity.BOTTOM,
        toastType: result.success ? ToastType.success : ToastType.error,
      );
    }
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return BaseActionButton(
      maxWidth: 110.0,
      iconData: Icons.delete_sweep_outlined,
      label: "delete".t(context: context),
      onPressed: () => _onTap(context, ref),
    );
  }
}
