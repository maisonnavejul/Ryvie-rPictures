import 'dart:async';

import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/domain/models/album/local_album.model.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/domain/services/sync_linked_album.service.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/extensions/build_context_extensions.dart';
import 'package:immich_mobile/extensions/platform_extensions.dart';
import 'package:immich_mobile/extensions/translate_extensions.dart';
import 'package:immich_mobile/providers/app_settings.provider.dart';
import 'package:immich_mobile/providers/background_sync.provider.dart';
import 'package:immich_mobile/providers/backup/backup_album.provider.dart';
import 'package:immich_mobile/providers/backup/drift_backup.provider.dart';
import 'package:immich_mobile/providers/infrastructure/platform.provider.dart';
import 'package:immich_mobile/providers/user.provider.dart';
import 'package:immich_mobile/services/app_settings.service.dart';
import 'package:immich_mobile/widgets/settings/settings_sub_page_scaffold.dart';
import 'package:logging/logging.dart';

class DriftBackupSettings extends ConsumerWidget {
  const DriftBackupSettings({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return SettingsSubPageScaffold(
      settings: [
        const _AutoBackupToggle(),
        const Divider(),
        Padding(
          padding: const EdgeInsets.only(left: 16.0),
          child: Text(
            "network_requirements".t(context: context).toUpperCase(),
            style: context.textTheme.labelSmall?.copyWith(color: context.colorScheme.onSurface.withValues(alpha: 0.7)),
          ),
        ),
        const _UseWifiForUploadVideosButton(),
        const _UseWifiForUploadPhotosButton(),
        if (CurrentPlatform.isIOS) ...[
          const Divider(),
          Padding(
            padding: const EdgeInsets.only(left: 16.0),
            child: Text(
              "iCloud".toUpperCase(),
              style: context.textTheme.labelSmall?.copyWith(
                color: context.colorScheme.onSurface.withValues(alpha: 0.7),
              ),
            ),
          ),
          const _IgnoreIcloudPhotosButton(),
        ],
        if (CurrentPlatform.isAndroid) ...[
          const Divider(),
          Padding(
            padding: const EdgeInsets.only(left: 16.0),
            child: Text(
              "background_options".t(context: context).toUpperCase(),
              style: context.textTheme.labelSmall?.copyWith(
                color: context.colorScheme.onSurface.withValues(alpha: 0.7),
              ),
            ),
          ),
          const _BackupOnlyWhenChargingButton(),
          const _BackupDelaySlider(),
        ],
        const Divider(),
        Padding(
          padding: const EdgeInsets.only(left: 16.0),
          child: Text(
            "backup_albums_sync".t(context: context).toUpperCase(),
            style: context.textTheme.labelSmall?.copyWith(color: context.colorScheme.onSurface.withValues(alpha: 0.7)),
          ),
        ),
        const _AlbumSyncActionButton(),
      ],
    );
  }
}

class _AutoBackupToggle extends ConsumerStatefulWidget {
  const _AutoBackupToggle();

  @override
  ConsumerState<_AutoBackupToggle> createState() => _AutoBackupToggleState();
}

class _AutoBackupToggleState extends ConsumerState<_AutoBackupToggle> {
  static final _logger = Logger("AutoBackupToggle");
  bool _isEnabled = false;

  @override
  void initState() {
    super.initState();
    _isEnabled = ref.read(appSettingsServiceProvider).getSetting(AppSettingsEnum.enableBackup);
  }

  Future<void> _onToggle(bool value) async {
    _logger.info("Auto backup toggled: $value");
    await ref.read(appSettingsServiceProvider).setSetting(AppSettingsEnum.enableBackup, value);
    setState(() => _isEnabled = value);

    if (value) {
      final currentUser = Store.tryGet(StoreKey.currentUser);
      if (currentUser == null) {
        _logger.warning("Cannot start backup: no current user");
        return;
      }
      final backupNotifier = ref.read(driftBackupProvider.notifier);
      // Skip if a sync is already running to avoid double-sync notifications
      if (ref.read(driftBackupProvider).isSyncing) {
        _logger.info("Sync already in progress, skipping toggle-triggered sync");
        return;
      }
      final backgroundSync = ref.read(backgroundSyncProvider);
      backupNotifier.updateSyncing(true);
      _logger.info("Starting remote sync before backup...");
      final success = await backgroundSync.syncRemote();
      if (!mounted) return;
      backupNotifier.updateSyncing(false);
      if (success) {
        _logger.info("Remote sync OK, starting backup");
        await backupNotifier.startBackup(currentUser.id);
      } else {
        _logger.warning("Remote sync failed, backup will not start");
      }
    } else {
      _logger.info("Auto backup disabled, canceling active uploads");
      await ref.read(driftBackupProvider.notifier).cancel();
    }
  }

  @override
  Widget build(BuildContext context) {
    final isCanceling = ref.watch(driftBackupProvider.select((s) => s.isCanceling));
    return ListTile(
      title: Text(
        "enable_backup".t(context: context),
        style: context.textTheme.titleMedium?.copyWith(color: context.primaryColor),
      ),
      subtitle: Text(
        "auto_backup_subtitle".t(context: context),
        style: context.textTheme.labelLarge,
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: Switch.adaptive(
        value: _isEnabled,
        onChanged: isCanceling ? null : _onToggle,
      ),
    );
  }
}

class _AlbumSyncActionButton extends ConsumerStatefulWidget {
  const _AlbumSyncActionButton();

  @override
  ConsumerState<_AlbumSyncActionButton> createState() => _AlbumSyncActionButtonState();
}

class _AlbumSyncActionButtonState extends ConsumerState<_AlbumSyncActionButton> {
  bool isAlbumSyncInProgress = false;

  Future<void> _manualSyncAlbums() async {
    setState(() {
      isAlbumSyncInProgress = true;
    });

    try {
      await ref.read(backgroundSyncProvider).syncLinkedAlbum();
      await ref.read(backgroundSyncProvider).syncRemote();
    } catch (_) {
    } finally {
      Future.delayed(const Duration(seconds: 1), () {
        setState(() {
          isAlbumSyncInProgress = false;
        });
      });
    }
  }

  Future<void> _manageLinkedAlbums() async {
    final currentUser = ref.read(currentUserProvider);
    if (currentUser == null) {
      return;
    }
    final localAlbums = ref.read(backupAlbumProvider);
    final selectedBackupAlbums = localAlbums
        .where((album) => album.backupSelection == BackupSelection.selected)
        .toList();

    await ref.read(syncLinkedAlbumServiceProvider).manageLinkedAlbums(selectedBackupAlbums, currentUser.id);
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      shrinkWrap: true,
      children: [
        StreamBuilder(
          stream: Store.watch(StoreKey.syncAlbums),
          initialData: Store.tryGet(StoreKey.syncAlbums) ?? false,
          builder: (context, snapshot) {
            final albumSyncEnable = snapshot.data ?? false;
            return Column(
              children: [
                ListTile(
                  title: Text(
                    "sync_albums".t(context: context),
                    style: context.textTheme.titleMedium?.copyWith(color: context.primaryColor),
                  ),
                  subtitle: Text(
                    "sync_upload_album_setting_subtitle".t(context: context),
                    style: context.textTheme.labelLarge,
                  ),
                  trailing: Switch(
                    value: albumSyncEnable,
                    onChanged: (bool newValue) async {
                      await ref.read(appSettingsServiceProvider).setSetting(AppSettingsEnum.syncAlbums, newValue);

                      if (newValue == true) {
                        await _manageLinkedAlbums();
                      }
                    },
                  ),
                ),
                AnimatedSize(
                  duration: const Duration(milliseconds: 300),
                  curve: Curves.easeInOut,
                  child: AnimatedOpacity(
                    duration: const Duration(milliseconds: 200),
                    opacity: albumSyncEnable ? 1.0 : 0.0,
                    child: albumSyncEnable
                        ? ListTile(
                            onTap: _manualSyncAlbums,
                            contentPadding: const EdgeInsets.only(left: 32, right: 16),
                            title: Text(
                              "organize_into_albums".t(context: context),
                              style: context.textTheme.titleSmall?.copyWith(
                                color: context.colorScheme.onSurface,
                                fontWeight: FontWeight.normal,
                              ),
                            ),
                            subtitle: Text(
                              "organize_into_albums_description".t(context: context),
                              style: context.textTheme.bodyMedium?.copyWith(
                                color: context.colorScheme.onSurface.withValues(alpha: 0.7),
                              ),
                            ),
                            trailing: isAlbumSyncInProgress
                                ? const SizedBox(
                                    width: 32,
                                    height: 32,
                                    child: CircularProgressIndicator.adaptive(strokeWidth: 2),
                                  )
                                : IconButton(
                                    onPressed: _manualSyncAlbums,
                                    icon: const Icon(Icons.sync_rounded),
                                    color: context.colorScheme.onSurface.withValues(alpha: 0.7),
                                    iconSize: 20,
                                    constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
                                  ),
                          )
                        : const SizedBox.shrink(),
                  ),
                ),
              ],
            );
          },
        ),
      ],
    );
  }
}

class _SettingsSwitchTile extends ConsumerStatefulWidget {
  final AppSettingsEnum<bool> appSettingsEnum;
  final String titleKey;
  final String subtitleKey;
  final void Function(bool?)? onChanged;

  const _SettingsSwitchTile({
    required this.appSettingsEnum,
    required this.titleKey,
    required this.subtitleKey,
    this.onChanged,
  });

  @override
  ConsumerState createState() => _SettingsSwitchTileState();
}

class _SettingsSwitchTileState extends ConsumerState<_SettingsSwitchTile> {
  late final Stream<bool?> valueStream;
  late final StreamSubscription<bool?> subscription;

  @override
  void initState() {
    super.initState();
    valueStream = Store.watch(widget.appSettingsEnum.storeKey).asBroadcastStream();
    subscription = valueStream.listen((value) {
      widget.onChanged?.call(value);
    });
  }

  @override
  void dispose() {
    subscription.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      title: Text(
        widget.titleKey.t(context: context),
        style: context.textTheme.titleMedium?.copyWith(color: context.primaryColor),
      ),
      subtitle: Text(widget.subtitleKey.t(context: context), style: context.textTheme.labelLarge),
      trailing: StreamBuilder(
        stream: valueStream,
        initialData: Store.tryGet(widget.appSettingsEnum.storeKey) ?? widget.appSettingsEnum.defaultValue,
        builder: (context, snapshot) {
          final value = snapshot.data ?? false;
          return Switch(
            value: value,
            onChanged: (bool newValue) async {
              await ref.read(appSettingsServiceProvider).setSetting(widget.appSettingsEnum, newValue);
            },
          );
        },
      ),
    );
  }
}

class _UseWifiForUploadVideosButton extends ConsumerWidget {
  const _UseWifiForUploadVideosButton();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return const _SettingsSwitchTile(
      appSettingsEnum: AppSettingsEnum.useCellularForUploadVideos,
      titleKey: "network_requirement_videos_upload",
      subtitleKey: "network_requirement_videos_upload_sub",
    );
  }
}

class _UseWifiForUploadPhotosButton extends ConsumerWidget {
  const _UseWifiForUploadPhotosButton();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return const _SettingsSwitchTile(
      appSettingsEnum: AppSettingsEnum.useCellularForUploadPhotos,
      titleKey: "network_requirement_photos_upload",
      subtitleKey: "network_requirement_photos_upload_sub",
    );
  }
}

class _IgnoreIcloudPhotosButton extends ConsumerWidget {
  const _IgnoreIcloudPhotosButton();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return const _SettingsSwitchTile(
      appSettingsEnum: AppSettingsEnum.ignoreIcloudAssets,
      titleKey: "ignore_icloud_photos",
      subtitleKey: "ignore_icloud_photos_description",
    );
  }
}

class _BackupOnlyWhenChargingButton extends ConsumerWidget {
  const _BackupOnlyWhenChargingButton();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return _SettingsSwitchTile(
      appSettingsEnum: AppSettingsEnum.backupRequireCharging,
      titleKey: "charging",
      subtitleKey: "charging_requirement_mobile_backup",
      onChanged: (value) {
        ref.read(backgroundWorkerFgServiceProvider).configure(requireCharging: value ?? false);
      },
    );
  }
}

class _BackupDelaySlider extends ConsumerStatefulWidget {
  const _BackupDelaySlider();

  @override
  ConsumerState<_BackupDelaySlider> createState() => _BackupDelaySliderState();
}

class _BackupDelaySliderState extends ConsumerState<_BackupDelaySlider> {
  late final Stream<int?> valueStream;
  late final StreamSubscription<int?> subscription;
  late int currentValue;

  static int backupDelayToSliderValue(int ms) => switch (ms) {
    5 => 0,
    30 => 1,
    120 => 2,
    _ => 3,
  };

  static int backupDelayToSeconds(int v) => switch (v) {
    0 => 5,
    1 => 30,
    2 => 120,
    _ => 600,
  };

  static String formatBackupDelaySliderValue(int v) => switch (v) {
    0 => 'setting_notifications_notify_seconds'.tr(namedArgs: {'count': '5'}),
    1 => 'setting_notifications_notify_seconds'.tr(namedArgs: {'count': '30'}),
    2 => 'setting_notifications_notify_minutes'.tr(namedArgs: {'count': '2'}),
    _ => 'setting_notifications_notify_minutes'.tr(namedArgs: {'count': '10'}),
  };

  @override
  void initState() {
    super.initState();
    final initialValue =
        Store.tryGet(AppSettingsEnum.backupTriggerDelay.storeKey) ?? AppSettingsEnum.backupTriggerDelay.defaultValue;
    currentValue = backupDelayToSliderValue(initialValue);

    valueStream = Store.watch(AppSettingsEnum.backupTriggerDelay.storeKey).asBroadcastStream();
    subscription = valueStream.listen((value) {
      if (mounted && value != null) {
        setState(() {
          currentValue = backupDelayToSliderValue(value);
        });
      }
    });
  }

  @override
  void dispose() {
    subscription.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(left: 16.0, top: 8.0),
          child: Text(
            'backup_controller_page_background_delay'.tr(
              namedArgs: {'duration': formatBackupDelaySliderValue(currentValue)},
            ),
            style: context.textTheme.titleMedium?.copyWith(color: context.primaryColor),
          ),
        ),
        Slider(
          value: currentValue.toDouble(),
          onChanged: (double v) {
            setState(() {
              currentValue = v.toInt();
            });
          },
          onChangeEnd: (double v) async {
            final milliseconds = backupDelayToSeconds(v.toInt());
            await ref.read(appSettingsServiceProvider).setSetting(AppSettingsEnum.backupTriggerDelay, milliseconds);
          },
          max: 3.0,
          min: 0.0,
          divisions: 3,
          label: formatBackupDelaySliderValue(currentValue),
        ),
      ],
    );
  }
}
