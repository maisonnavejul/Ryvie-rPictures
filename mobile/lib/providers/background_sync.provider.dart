import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/domain/utils/background_sync.dart';
import 'package:immich_mobile/providers/backup/drift_backup.provider.dart';
import 'package:immich_mobile/providers/infrastructure/memory.provider.dart';
import 'package:immich_mobile/providers/sync_status.provider.dart';

final backgroundSyncProvider = Provider<BackgroundSyncManager>((ref) {
  final syncStatusNotifier = ref.read(syncStatusProvider.notifier);
  final backupProvider = ref.read(driftBackupProvider.notifier);

  final manager = BackgroundSyncManager(
    onRemoteSyncStart: () {
      syncStatusNotifier.startRemoteSync();
      backupProvider.updateError(BackupError.none);
    },
    onRemoteSyncComplete: (isSuccess) {
      syncStatusNotifier.completeRemoteSync();
      backupProvider.updateError(isSuccess == true ? BackupError.none : BackupError.syncFailed);
      if (isSuccess == true) {
        // Les souvenirs ("il y a 1 an", etc.) sont calculés une seule fois au
        // premier affichage, souvent avant que la sync ait ramené les données.
        // On les recalcule à chaque fin de sync pour ne pas devoir redémarrer.
        ref.invalidate(driftMemoryFutureProvider);
      }
    },
    onRemoteSyncError: syncStatusNotifier.errorRemoteSync,
    onLocalSyncStart: syncStatusNotifier.startLocalSync,
    onLocalSyncComplete: syncStatusNotifier.completeLocalSync,
    onLocalSyncError: syncStatusNotifier.errorLocalSync,
    onHashingStart: syncStatusNotifier.startHashJob,
    onHashingComplete: syncStatusNotifier.completeHashJob,
    onHashingError: syncStatusNotifier.errorHashJob,
  );
  ref.onDispose(manager.cancel);
  return manager;
});
