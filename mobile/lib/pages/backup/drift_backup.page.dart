import 'dart:async';

import 'package:auto_route/auto_route.dart';
import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/domain/models/album/local_album.model.dart';
import 'package:immich_mobile/extensions/build_context_extensions.dart';
import 'package:immich_mobile/extensions/theme_extensions.dart';
import 'package:immich_mobile/extensions/translate_extensions.dart';
import 'package:immich_mobile/generated/intl_keys.g.dart';
import 'package:immich_mobile/providers/background_sync.provider.dart';
import 'package:immich_mobile/providers/backup/backup_album.provider.dart';
import 'package:immich_mobile/providers/backup/drift_backup.provider.dart';
import 'package:immich_mobile/providers/sync_status.provider.dart';
import 'package:immich_mobile/providers/user.provider.dart';
import 'package:immich_mobile/routing/router.dart';
import 'package:immich_mobile/utils/bytes_units.dart';
import 'package:immich_mobile/widgets/backup/backup_info_card.dart';
import 'package:path/path.dart' as path;
import 'package:wakelock_plus/wakelock_plus.dart';

@RoutePage()
class DriftBackupPage extends ConsumerStatefulWidget {
  const DriftBackupPage({super.key});

  @override
  ConsumerState<DriftBackupPage> createState() => _DriftBackupPageState();
}

class _DriftBackupPageState extends ConsumerState<DriftBackupPage> {
  bool? syncSuccess;

  @override
  void initState() {
    super.initState();

    WakelockPlus.enable();

    final currentUser = ref.read(currentUserProvider);
    if (currentUser == null) {
      return;
    }

    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!mounted) return;
      await ref.read(driftBackupProvider.notifier).getBackupStatus(currentUser.id);

      // Skip if a sync is already running (e.g. triggered by the auto-backup toggle)
      if (!mounted || ref.read(driftBackupProvider).isSyncing) return;

      ref.read(driftBackupProvider.notifier).updateSyncing(true);
      syncSuccess = await ref.read(backgroundSyncProvider).syncRemote();

      if (!mounted) return;
      ref.read(driftBackupProvider.notifier).updateSyncing(false);
      await ref.read(driftBackupProvider.notifier).getBackupStatus(currentUser.id);
    });
  }

  @override
  dispose() {
    super.dispose();
    WakelockPlus.disable();
  }

  @override
  Widget build(BuildContext context) {
    final selectedAlbum = ref
        .watch(backupAlbumProvider)
        .where((album) => album.backupSelection == BackupSelection.selected)
        .toList();

    final error = ref.watch(driftBackupProvider.select((p) => p.error));

    return Scaffold(
      appBar: AppBar(
        elevation: 0,
        title: Text("backup_controller_page_backup".t()),
        leading: IconButton(
          onPressed: () {
            context.maybePop(true);
          },
          splashRadius: 24,
          icon: const Icon(Icons.arrow_back_ios_rounded),
        ),
        actions: [
          IconButton(
            onPressed: () {
              context.pushRoute(const DriftBackupOptionsRoute());
            },
            icon: const Icon(Icons.settings_outlined),
            tooltip: "backup_options".t(context: context),
          ),
        ],
      ),
      body: Stack(
        children: [
          Padding(
            padding: const EdgeInsets.only(left: 16.0, right: 16, bottom: 32),
            child: ListView(
              children: [
                const SizedBox(height: 8),
                const _BackupAlbumSelectionCard(),
                if (selectedAlbum.isNotEmpty) ...[
                  const _TotalCard(),
                  const _BackupCard(),
                  const _RemainderCard(),
                  const _PreparingStatus(),
                  const _UploadProgressCard(),
                  switch (error) {
                    BackupError.none => const SizedBox.shrink(),
                    BackupError.syncFailed => Padding(
                      padding: const EdgeInsets.only(top: 10),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        crossAxisAlignment: CrossAxisAlignment.center,
                        mainAxisSize: MainAxisSize.max,
                        children: [
                          Icon(Icons.warning_rounded, color: context.colorScheme.error, fill: 1),
                          const SizedBox(width: 8),
                          Text(
                            IntlKeys.backup_error_sync_failed.t(),
                            style: context.textTheme.bodyMedium?.copyWith(color: context.colorScheme.error),
                            textAlign: TextAlign.center,
                          ),
                        ],
                      ),
                    ),
                  },
                  TextButton.icon(
                    icon: const Icon(Icons.info_outline_rounded),
                    onPressed: () => context.pushRoute(const DriftUploadDetailRoute()),
                    label: Text("view_details".t(context: context)),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _BackupAlbumSelectionCard extends ConsumerWidget {
  const _BackupAlbumSelectionCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    Widget buildSelectedAlbumName() {
      String text = "backup_controller_page_backup_selected".tr();
      final albums = ref
          .watch(backupAlbumProvider)
          .where((album) => album.backupSelection == BackupSelection.selected)
          .toList();

      if (albums.isNotEmpty) {
        for (var album in albums) {
          if (album.name == "Recent" || album.name == "Recents") {
            text += "${album.name} (${'all'.tr()}), ";
          } else {
            text += "${album.name}, ";
          }
        }

        return Padding(
          padding: const EdgeInsets.only(top: 8.0),
          child: Text(
            text.trim().substring(0, text.length - 2),
            style: context.textTheme.labelLarge?.copyWith(color: context.primaryColor),
          ),
        );
      } else {
        return Padding(
          padding: const EdgeInsets.only(top: 8.0),
          child: Text(
            "backup_controller_page_none_selected".tr(),
            style: context.textTheme.labelLarge?.copyWith(color: context.primaryColor),
          ),
        );
      }
    }

    Widget buildExcludedAlbumName() {
      String text = "backup_controller_page_excluded".tr();
      final albums = ref
          .watch(backupAlbumProvider)
          .where((album) => album.backupSelection == BackupSelection.excluded)
          .toList();

      if (albums.isNotEmpty) {
        for (var album in albums) {
          text += "${album.name}, ";
        }

        return Padding(
          padding: const EdgeInsets.only(top: 8.0),
          child: Text(
            text.trim().substring(0, text.length - 2),
            style: context.textTheme.labelLarge?.copyWith(color: Colors.red[300]),
          ),
        );
      } else {
        return const SizedBox();
      }
    }

    return Card(
      shape: RoundedRectangleBorder(
        borderRadius: const BorderRadius.all(Radius.circular(20)),
        side: BorderSide(color: context.colorScheme.outlineVariant, width: 1),
      ),
      elevation: 0,
      borderOnForeground: false,
      child: ListTile(
        minVerticalPadding: 18,
        title: Text("backup_controller_page_albums", style: context.textTheme.titleMedium).tr(),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 8.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                "backup_controller_page_to_backup",
                style: context.textTheme.bodyMedium?.copyWith(color: context.colorScheme.onSurfaceSecondary),
              ).tr(),
              buildSelectedAlbumName(),
              buildExcludedAlbumName(),
            ],
          ),
        ),
        trailing: ElevatedButton(
          onPressed: () async {
            await context.pushRoute(const DriftBackupAlbumSelectionRoute());
            final currentUser = ref.read(currentUserProvider);
            if (currentUser == null) {
              return;
            }
            unawaited(ref.read(driftBackupProvider.notifier).getBackupStatus(currentUser.id));
          },
          child: const Text("select", style: TextStyle(fontWeight: FontWeight.bold)).tr(),
        ),
      ),
    );
  }
}

class _TotalCard extends ConsumerWidget {
  const _TotalCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final totalCount = ref.watch(driftBackupProvider.select((p) => p.totalCount));

    return BackupInfoCard(
      title: "total".tr(),
      subtitle: "backup_controller_page_total_sub".tr(),
      info: totalCount.toString(),
    );
  }
}

class _BackupCard extends ConsumerWidget {
  const _BackupCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final backupCount = ref.watch(driftBackupProvider.select((p) => p.backupCount));
    final syncStatus = ref.watch(syncStatusProvider);

    return BackupInfoCard(
      title: "backup_controller_page_backup".tr(),
      subtitle: "backup_controller_page_backup_sub".tr(),
      info: backupCount.toString(),
      isLoading: syncStatus.isRemoteSyncing,
    );
  }
}

class _RemainderCard extends ConsumerWidget {
  const _RemainderCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final remainderCount = ref.watch(driftBackupProvider.select((p) => p.remainderCount));
    final syncStatus = ref.watch(syncStatusProvider);

    return Card(
      shape: RoundedRectangleBorder(
        borderRadius: const BorderRadius.all(Radius.circular(20)),
        side: BorderSide(color: context.colorScheme.outlineVariant, width: 1),
      ),
      elevation: 0,
      borderOnForeground: false,
      child: Column(
        children: [
          ListTile(
            minVerticalPadding: 18,
            isThreeLine: true,
            title: Text("backup_controller_page_remainder".t(context: context), style: context.textTheme.titleMedium),
            subtitle: Padding(
              padding: const EdgeInsets.only(top: 4.0, right: 18.0),
              child: Text(
                "backup_controller_page_remainder_sub".t(context: context),
                style: context.textTheme.bodyMedium?.copyWith(color: context.colorScheme.onSurfaceSecondary),
              ),
            ),
            trailing: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Stack(
                  children: [
                    Text(
                      remainderCount.toString(),
                      style: context.textTheme.titleLarge?.copyWith(
                        color: context.colorScheme.onSurface.withAlpha(syncStatus.isRemoteSyncing ? 50 : 255),
                      ),
                    ),
                    if (syncStatus.isRemoteSyncing)
                      Positioned.fill(
                        child: Align(
                          alignment: Alignment.center,
                          child: SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: context.colorScheme.onSurface.withAlpha(150),
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
                Text(
                  "backup_info_card_assets",
                  style: context.textTheme.labelLarge?.copyWith(
                    color: context.colorScheme.onSurface.withAlpha(syncStatus.isRemoteSyncing ? 50 : 255),
                  ),
                ).tr(),
              ],
            ),
          ),
          const Divider(height: 0),
          ListTile(
            enableFeedback: true,
            visualDensity: VisualDensity.compact,
            contentPadding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 0.0),
            shape: const RoundedRectangleBorder(
              borderRadius: BorderRadius.only(bottomLeft: Radius.circular(20), bottomRight: Radius.circular(20)),
            ),
            onTap: () => context.pushRoute(const DriftBackupAssetDetailRoute()),
            title: Text(
              "view_details".t(context: context),
              style: context.textTheme.labelLarge?.copyWith(color: context.colorScheme.onSurface.withAlpha(200)),
            ),
            trailing: Icon(Icons.arrow_forward_ios, size: 16, color: context.colorScheme.onSurfaceVariant),
          ),
        ],
      ),
    );
  }
}

class _UploadProgressCard extends ConsumerWidget {
  const _UploadProgressCard();

  String _formatDuration(Duration duration) {
    if (duration.inHours > 0) {
      return '${duration.inHours}h ${duration.inMinutes.remainder(60)}min';
    }
    if (duration.inMinutes > 0) {
      return '${duration.inMinutes}min ${duration.inSeconds.remainder(60)}s';
    }
    return '${duration.inSeconds}s';
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final backupState = ref.watch(driftBackupProvider);
    final uploadItems = backupState.uploadItems;

    if (!backupState.isActive) {
      return const SizedBox.shrink();
    }

    final isSyncing = backupState.isSyncing && uploadItems.isEmpty && backupState.enqueueTotalCount == 0;
    final isStartingNoEnqueueYet = backupState.isStartingBackup &&
        backupState.enqueueTotalCount == 0 &&
        uploadItems.isEmpty &&
        !backupState.isSyncing;
    final isEnqueuing = backupState.enqueueTotalCount > 0 && uploadItems.isEmpty;
    final isLooseProgress = isSyncing || isStartingNoEnqueueYet || isEnqueuing;

    final completed = backupState.sessionCompletedCount;
    final total = backupState.sessionTotalCount;
    final progress = backupState.sessionProgress;
    final eta = backupState.estimatedTimeRemaining;

    final activeUploads = uploadItems.values.where((item) => item.isFailed != true).toList();
    final failedCount = uploadItems.values.where((item) => item.isFailed == true).length;

    String headerLabel;
    if (isSyncing) {
      headerLabel = 'Synchronisation...';
    } else if (isStartingNoEnqueueYet) {
      if (backupState.prepCandidateTotal > 0) {
        headerLabel = 'Préparation... ${backupState.prepCandidateProcessed} / ${backupState.prepCandidateTotal}';
      } else {
        headerLabel = 'Préparation des fichiers...';
      }
    } else if (isEnqueuing) {
      headerLabel = 'Préparation... ${backupState.enqueueCount} / ${backupState.enqueueTotalCount}';
    } else {
      headerLabel = 'Upload en cours';
    }

    return Card(
      margin: const EdgeInsets.only(top: 8),
      shape: RoundedRectangleBorder(
        borderRadius: const BorderRadius.all(Radius.circular(20)),
        side: BorderSide(color: context.colorScheme.outlineVariant, width: 1),
      ),
      elevation: 0,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                if (isLooseProgress)
                  SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2, color: context.primaryColor),
                  )
                else
                  Icon(Icons.cloud_upload_rounded, color: context.primaryColor, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    headerLabel,
                    style: context.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (!isLooseProgress)
                  Text(
                    '$completed / $total',
                    style: context.textTheme.titleMedium?.copyWith(
                      color: context.primaryColor,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 12),
            ClipRRect(
              borderRadius: const BorderRadius.all(Radius.circular(8)),
              child: isLooseProgress
                  ? LinearProgressIndicator(
                      minHeight: 8,
                      backgroundColor: context.colorScheme.surfaceContainerHighest,
                      color: context.primaryColor,
                    )
                  : TweenAnimationBuilder<double>(
                      tween: Tween(begin: 0, end: progress),
                      duration: const Duration(milliseconds: 500),
                      builder: (context, value, _) => LinearProgressIndicator(
                        value: value,
                        minHeight: 8,
                        backgroundColor: context.colorScheme.surfaceContainerHighest,
                        color: context.primaryColor,
                      ),
                    ),
            ),
            if (!isLooseProgress) ...[
            const SizedBox(height: 8),
            Row(
              children: [
                Text(
                  '${(progress * 100).toStringAsFixed(1)}%',
                  style: context.textTheme.labelMedium?.copyWith(
                    color: context.primaryColor,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                if (backupState.sessionUploadedBytes > 0) ...[
                  const SizedBox(width: 8),
                  Text(
                    formatHumanReadableBytes(backupState.sessionUploadedBytes, 1),
                    style: context.textTheme.labelMedium?.copyWith(
                      color: context.colorScheme.onSurface.withValues(alpha: 0.6),
                    ),
                  ),
                ],
                const Spacer(),
                if (eta != null)
                  Row(
                    children: [
                      Icon(
                        Icons.timer_outlined,
                        size: 14,
                        color: context.colorScheme.onSurface.withValues(alpha: 0.6),
                      ),
                      const SizedBox(width: 4),
                      Text(
                        '~${_formatDuration(eta)}',
                        style: context.textTheme.labelMedium?.copyWith(
                          color: context.colorScheme.onSurface.withValues(alpha: 0.6),
                        ),
                      ),
                    ],
                  ),
              ],
            ),
            if (failedCount > 0) ...[
              const SizedBox(height: 8),
              Row(
                children: [
                  Icon(Icons.error_outline, size: 14, color: context.colorScheme.error),
                  const SizedBox(width: 4),
                  Text(
                    '$failedCount fichier${failedCount > 1 ? 's' : ''} en erreur',
                    style: context.textTheme.labelMedium?.copyWith(color: context.colorScheme.error),
                  ),
                ],
              ),
            ],
            if (activeUploads.isNotEmpty) ...[
              const Divider(height: 20),
              ...activeUploads.take(3).map((item) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            path.basename(item.filename),
                            style: context.textTheme.bodySmall?.copyWith(fontWeight: FontWeight.w500),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(height: 4),
                          ClipRRect(
                            borderRadius: const BorderRadius.all(Radius.circular(4)),
                            child: LinearProgressIndicator(
                              value: item.progress.clamp(0.0, 1.0),
                              minHeight: 4,
                              backgroundColor: context.colorScheme.surfaceContainerHighest,
                              color: context.colorScheme.secondary,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        Text(
                          '${(item.progress * 100).clamp(0, 100).toStringAsFixed(0)}%',
                          style: context.textTheme.labelSmall?.copyWith(fontWeight: FontWeight.bold),
                        ),
                        if (item.networkSpeedAsString.isNotEmpty)
                          Text(
                            item.networkSpeedAsString,
                            style: context.textTheme.labelSmall?.copyWith(
                              color: context.colorScheme.onSurface.withValues(alpha: 0.5),
                              fontSize: 10,
                            ),
                          ),
                      ],
                    ),
                  ],
                ),
              )),
              if (activeUploads.length > 3)
                Text(
                  '+${activeUploads.length - 3} autre${activeUploads.length - 3 > 1 ? 's' : ''}...',
                  style: context.textTheme.labelSmall?.copyWith(
                    color: context.colorScheme.onSurface.withValues(alpha: 0.5),
                  ),
                ),
            ],
            ], // end if (!isPreparing && !isEnqueuing)
          ],
        ),
      ),
    );
  }
}

class _PreparingStatus extends ConsumerStatefulWidget {
  const _PreparingStatus();

  @override
  _PreparingStatusState createState() => _PreparingStatusState();
}

class _PreparingStatusState extends ConsumerState {
  Timer? _pollingTimer;

  @override
  void dispose() {
    _pollingTimer?.cancel();
    super.dispose();
  }

  void _startPollingIfNeeded() {
    if (_pollingTimer != null) return;

    _pollingTimer = Timer.periodic(const Duration(seconds: 3), (timer) async {
      final currentUser = ref.read(currentUserProvider);
      if (currentUser != null && mounted) {
        await ref.read(driftBackupProvider.notifier).getBackupStatus(currentUser.id);

        // Stop polling if processing count reaches 0
        final updatedProcessingCount = ref.read(driftBackupProvider.select((p) => p.processingCount));
        if (updatedProcessingCount == 0) {
          timer.cancel();
          _pollingTimer = null;
        }
      } else {
        timer.cancel();
        _pollingTimer = null;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final syncStatus = ref.watch(syncStatusProvider);
    final remainderCount = ref.watch(driftBackupProvider.select((p) => p.remainderCount));
    final processingCount = ref.watch(driftBackupProvider.select((p) => p.processingCount));
    final readyForUploadCount = remainderCount - processingCount;

    ref.listen<int>(driftBackupProvider.select((p) => p.processingCount), (previous, next) {
      if (next > 0 && _pollingTimer == null) {
        _startPollingIfNeeded();
      } else if (next == 0 && _pollingTimer != null) {
        _pollingTimer?.cancel();
        _pollingTimer = null;
      }
    });

    if (!syncStatus.isHashing) {
      return const SizedBox.shrink();
    }

    return Card(
      margin: const EdgeInsets.only(top: 8),
      shape: RoundedRectangleBorder(
        borderRadius: const BorderRadius.all(Radius.circular(20)),
        side: BorderSide(color: context.colorScheme.outlineVariant, width: 1),
      ),
      elevation: 0,
      clipBehavior: Clip.antiAlias,
      child: Row(
        children: [
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 12),
              color: context.colorScheme.surfaceContainerHigh.withValues(alpha: 0.5),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        "preparing".t(context: context),
                        style: context.textTheme.labelLarge?.copyWith(
                          color: context.colorScheme.onSurface.withAlpha(200),
                        ),
                      ),
                      const SizedBox(width: 8),
                      const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 1.5)),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    processingCount.toString(),
                    style: context.textTheme.titleMedium?.copyWith(
                      color: context.colorScheme.primary,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 12),
              color: context.colorScheme.primary.withValues(alpha: 0.1),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(
                    "ready_for_upload".t(context: context),
                    style: context.textTheme.labelLarge?.copyWith(color: context.colorScheme.onSurface.withAlpha(200)),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    readyForUploadCount.toString(),
                    style: context.textTheme.titleMedium?.copyWith(
                      color: context.primaryColor,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
