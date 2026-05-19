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

/// This delete action has the following behavior:
/// - Set the deletedAt information, put the asset in the trash in the server
/// which will be permanently deleted after the number of days configure by the admin
class TrashActionButton extends ConsumerStatefulWidget {
  final ActionSource source;

  const TrashActionButton({super.key, required this.source});

  @override
  ConsumerState<TrashActionButton> createState() => _TrashActionButtonState();
}

class _TrashActionButtonState extends ConsumerState<TrashActionButton> {
  static final _log = Logger("TrashActionButton");
  bool _isProcessing = false;

  Future<void> _onTap() async {
    if (_isProcessing) {
      _log.info("Trash action already in progress, ignoring tap");
      return;
    }
    if (!mounted) return;

    final selectedCount = ref.read(multiSelectProvider).selectedAssets.length;
    _log.info("Trash action started for $selectedCount asset(s) from ${widget.source.name}");
    setState(() => _isProcessing = true);

    final sw = Stopwatch()..start();
    final result = await ref.read(actionProvider.notifier).trash(widget.source);
    sw.stop();
    _log.info(
      "Trash action done in ${sw.elapsed.inSeconds}s — "
      "success=${result.success}, count=${result.count}"
      "${result.error != null ? ', error=${result.error}' : ''}",
    );

    if (!mounted) return;

    ref.read(multiSelectProvider.notifier).reset();

    if (widget.source == ActionSource.viewer) {
      EventStream.shared.emit(const ViewerReloadAssetEvent());
    }

    final successMessage = 'trash_action_prompt'.t(context: context, args: {'count': result.count.toString()});

    if (mounted) {
      ImmichToast.show(
        context: context,
        msg: result.success ? successMessage : 'scaffold_body_error_occurred'.t(context: context),
        gravity: ToastGravity.BOTTOM,
        toastType: result.success ? ToastType.success : ToastType.error,
      );
      setState(() => _isProcessing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return BaseActionButton(
      maxWidth: 85.0,
      iconData: _isProcessing ? Icons.hourglass_top_rounded : Icons.delete_outline_rounded,
      label: "control_bottom_app_bar_trash_from_immich".t(context: context),
      onPressed: _isProcessing ? null : _onTap,
    );
  }
}
