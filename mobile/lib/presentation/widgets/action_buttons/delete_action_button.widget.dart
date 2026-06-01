import 'package:flutter/material.dart';
import 'package:fluttertoast/fluttertoast.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/constants/enums.dart';
import 'package:immich_mobile/domain/utils/event_stream.dart';
import 'package:immich_mobile/extensions/translate_extensions.dart';
import 'package:immich_mobile/presentation/widgets/action_buttons/base_action_button.widget.dart';
import 'package:immich_mobile/presentation/widgets/asset_viewer/asset_viewer.state.dart';
import 'package:immich_mobile/providers/infrastructure/action.provider.dart';
import 'package:immich_mobile/providers/timeline/multiselect.provider.dart';
import 'package:immich_mobile/widgets/common/immich_toast.dart';
import 'package:logging/logging.dart';

/// Bouton "Supprimer" unifié : met le serveur en corbeille ET supprime
/// les copies locales sur iPhone. iOS affiche automatiquement sa popup
/// de permission PhotoKit pour la suppression locale — si l'utilisateur
/// refuse, seule la copie serveur est mise en corbeille.
class DeleteActionButton extends ConsumerStatefulWidget {
  final ActionSource source;
  // Gardé pour compat avec l'API existante mais non utilisé : iOS gère
  // déjà la confirmation pour la suppression locale.
  final bool showConfirmation;
  const DeleteActionButton({super.key, required this.source, this.showConfirmation = false});

  @override
  ConsumerState<DeleteActionButton> createState() => _DeleteActionButtonState();
}

class _DeleteActionButtonState extends ConsumerState<DeleteActionButton> {
  static final _log = Logger("DeleteActionButton");
  bool _isProcessing = false;

  Future<void> _onTap() async {
    if (_isProcessing) return;
    if (!mounted) return;

    final selectedCount = ref.read(multiSelectProvider).selectedAssets.length;
    _log.info("Delete action started for $selectedCount asset(s) from ${widget.source.name}");
    setState(() => _isProcessing = true);

    final sw = Stopwatch()..start();
    final result = await ref.read(actionProvider.notifier).trashRemoteAndDeleteLocal(widget.source);
    sw.stop();
    _log.info(
      "Delete action done in ${sw.elapsed.inSeconds}s — "
      "success=${result.success}, count=${result.count}"
      "${result.error != null ? ', error=${result.error}' : ''}",
    );

    if (!mounted) return;
    ref.read(multiSelectProvider.notifier).reset();

    if (widget.source == ActionSource.viewer) {
      EventStream.shared.emit(const ViewerReloadAssetEvent());
    }

    final successMessage = 'delete_action_prompt'.t(context: context, args: {'count': result.count.toString()});
    ImmichToast.show(
      context: context,
      msg: result.success ? successMessage : 'scaffold_body_error_occurred'.t(context: context),
      gravity: ToastGravity.BOTTOM,
      toastType: result.success ? ToastType.success : ToastType.error,
    );

    if (mounted) {
      setState(() => _isProcessing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return BaseActionButton(
      maxWidth: 110.0,
      iconData: _isProcessing ? Icons.hourglass_top_rounded : Icons.delete_outline_rounded,
      label: "delete".t(context: context),
      onPressed: _isProcessing ? null : _onTap,
    );
  }
}
