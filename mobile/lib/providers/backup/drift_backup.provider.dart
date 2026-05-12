// ignore_for_file: public_member_api_docs, sort_constructors_first
import 'dart:async';

import 'package:background_downloader/background_downloader.dart';
import 'package:collection/collection.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/constants/constants.dart';
import 'package:immich_mobile/domain/models/album/local_album.model.dart';
import 'package:immich_mobile/domain/models/asset/base_asset.model.dart';
import 'package:immich_mobile/extensions/string_extensions.dart';
import 'package:immich_mobile/infrastructure/repositories/backup.repository.dart';
import 'package:immich_mobile/providers/infrastructure/asset.provider.dart';
import 'package:immich_mobile/providers/user.provider.dart';
import 'package:immich_mobile/services/upload.service.dart';
import 'package:immich_mobile/utils/debug_print.dart';
import 'package:logging/logging.dart';

class EnqueueStatus {
  final int enqueueCount;
  final int totalCount;

  const EnqueueStatus({required this.enqueueCount, required this.totalCount});

  EnqueueStatus copyWith({int? enqueueCount, int? totalCount}) {
    return EnqueueStatus(enqueueCount: enqueueCount ?? this.enqueueCount, totalCount: totalCount ?? this.totalCount);
  }

  @override
  String toString() => 'EnqueueStatus(enqueueCount: $enqueueCount, totalCount: $totalCount)';
}

class DriftUploadStatus {
  final String taskId;
  final String filename;
  final double progress;
  final int fileSize;
  final String networkSpeedAsString;
  final bool? isFailed;
  final String? error;

  const DriftUploadStatus({
    required this.taskId,
    required this.filename,
    required this.progress,
    required this.fileSize,
    required this.networkSpeedAsString,
    this.isFailed,
    this.error,
  });

  DriftUploadStatus copyWith({
    String? taskId,
    String? filename,
    double? progress,
    int? fileSize,
    String? networkSpeedAsString,
    bool? isFailed,
    String? error,
  }) {
    return DriftUploadStatus(
      taskId: taskId ?? this.taskId,
      filename: filename ?? this.filename,
      progress: progress ?? this.progress,
      fileSize: fileSize ?? this.fileSize,
      networkSpeedAsString: networkSpeedAsString ?? this.networkSpeedAsString,
      isFailed: isFailed ?? this.isFailed,
      error: error ?? this.error,
    );
  }

  @override
  String toString() {
    return 'DriftUploadStatus(taskId: $taskId, filename: $filename, progress: $progress, fileSize: $fileSize, networkSpeedAsString: $networkSpeedAsString, isFailed: $isFailed, error: $error)';
  }

  @override
  bool operator ==(covariant DriftUploadStatus other) {
    if (identical(this, other)) return true;

    return other.taskId == taskId &&
        other.filename == filename &&
        other.progress == progress &&
        other.fileSize == fileSize &&
        other.networkSpeedAsString == networkSpeedAsString &&
        other.isFailed == isFailed &&
        other.error == error;
  }

  @override
  int get hashCode {
    return taskId.hashCode ^
        filename.hashCode ^
        progress.hashCode ^
        fileSize.hashCode ^
        networkSpeedAsString.hashCode ^
        isFailed.hashCode ^
        error.hashCode;
  }
}

enum BackupError { none, syncFailed }

class DriftBackupState {
  final int totalCount;
  final int backupCount;
  final int remainderCount;
  final int processingCount;

  final int enqueueCount;
  final int enqueueTotalCount;

  final bool isSyncing;
  final bool isCanceling;
  final BackupError error;

  final Map<String, DriftUploadStatus> uploadItems;

  final int sessionCompletedCount;
  final int sessionTotalCount;
  final DateTime? sessionStartTime;
  final int sessionUploadedBytes;
  final bool isStartingBackup;
  final int prepCandidateTotal;
  final int prepCandidateProcessed;

  const DriftBackupState({
    required this.totalCount,
    required this.backupCount,
    required this.remainderCount,
    required this.processingCount,
    required this.enqueueCount,
    required this.enqueueTotalCount,
    required this.isCanceling,
    required this.isSyncing,
    required this.uploadItems,
    this.error = BackupError.none,
    this.sessionCompletedCount = 0,
    this.sessionTotalCount = 0,
    this.sessionStartTime,
    this.sessionUploadedBytes = 0,
    this.isStartingBackup = false,
    this.prepCandidateTotal = 0,
    this.prepCandidateProcessed = 0,
  });

  DriftBackupState copyWith({
    int? totalCount,
    int? backupCount,
    int? remainderCount,
    int? processingCount,
    int? enqueueCount,
    int? enqueueTotalCount,
    bool? isCanceling,
    bool? isSyncing,
    Map<String, DriftUploadStatus>? uploadItems,
    BackupError? error,
    int? sessionCompletedCount,
    int? sessionTotalCount,
    DateTime? sessionStartTime,
    int? sessionUploadedBytes,
    bool? isStartingBackup,
    int? prepCandidateTotal,
    int? prepCandidateProcessed,
  }) {
    return DriftBackupState(
      totalCount: totalCount ?? this.totalCount,
      backupCount: backupCount ?? this.backupCount,
      remainderCount: remainderCount ?? this.remainderCount,
      processingCount: processingCount ?? this.processingCount,
      enqueueCount: enqueueCount ?? this.enqueueCount,
      enqueueTotalCount: enqueueTotalCount ?? this.enqueueTotalCount,
      isCanceling: isCanceling ?? this.isCanceling,
      isSyncing: isSyncing ?? this.isSyncing,
      uploadItems: uploadItems ?? this.uploadItems,
      error: error ?? this.error,
      sessionCompletedCount: sessionCompletedCount ?? this.sessionCompletedCount,
      sessionTotalCount: sessionTotalCount ?? this.sessionTotalCount,
      sessionStartTime: sessionStartTime ?? this.sessionStartTime,
      sessionUploadedBytes: sessionUploadedBytes ?? this.sessionUploadedBytes,
      isStartingBackup: isStartingBackup ?? this.isStartingBackup,
      prepCandidateTotal: prepCandidateTotal ?? this.prepCandidateTotal,
      prepCandidateProcessed: prepCandidateProcessed ?? this.prepCandidateProcessed,
    );
  }

  bool get isUploading => uploadItems.isNotEmpty && !isCanceling;

  bool get isActive =>
      (isSyncing ||
              isStartingBackup ||
              enqueueTotalCount > 0 ||
              processingCount > 0 ||
              uploadItems.isNotEmpty) &&
          !isCanceling;

  double get sessionProgress {
    if (sessionTotalCount == 0) return 0;
    return sessionCompletedCount / sessionTotalCount;
  }

  Duration? get estimatedTimeRemaining {
    if (sessionStartTime == null || sessionCompletedCount == 0) return null;
    final elapsed = DateTime.now().difference(sessionStartTime!);
    final remaining = sessionTotalCount - sessionCompletedCount;
    if (remaining <= 0) return Duration.zero;
    final msPerFile = elapsed.inMilliseconds / sessionCompletedCount;
    return Duration(milliseconds: (msPerFile * remaining).round());
  }

  @override
  String toString() {
    return 'DriftBackupState(totalCount: $totalCount, backupCount: $backupCount, remainderCount: $remainderCount, processingCount: $processingCount, enqueueCount: $enqueueCount, enqueueTotalCount: $enqueueTotalCount, isCanceling: $isCanceling, isSyncing: $isSyncing, uploadItems: $uploadItems, error: $error)';
  }

  @override
  bool operator ==(covariant DriftBackupState other) {
    if (identical(this, other)) return true;
    final mapEquals = const DeepCollectionEquality().equals;

    return other.totalCount == totalCount &&
        other.backupCount == backupCount &&
        other.remainderCount == remainderCount &&
        other.processingCount == processingCount &&
        other.enqueueCount == enqueueCount &&
        other.enqueueTotalCount == enqueueTotalCount &&
        other.isCanceling == isCanceling &&
        other.isSyncing == isSyncing &&
        mapEquals(other.uploadItems, uploadItems) &&
        other.error == error &&
        other.sessionCompletedCount == sessionCompletedCount &&
        other.sessionTotalCount == sessionTotalCount &&
        other.sessionUploadedBytes == sessionUploadedBytes;
  }

  @override
  int get hashCode {
    return totalCount.hashCode ^
        backupCount.hashCode ^
        remainderCount.hashCode ^
        processingCount.hashCode ^
        enqueueCount.hashCode ^
        enqueueTotalCount.hashCode ^
        isCanceling.hashCode ^
        isSyncing.hashCode ^
        uploadItems.hashCode ^
        error.hashCode ^
        sessionCompletedCount.hashCode ^
        sessionTotalCount.hashCode ^
        sessionUploadedBytes.hashCode;
  }
}

final driftBackupProvider = StateNotifierProvider<DriftBackupNotifier, DriftBackupState>((ref) {
  return DriftBackupNotifier(ref.watch(uploadServiceProvider));
});

class DriftBackupNotifier extends StateNotifier<DriftBackupState> {
  DriftBackupNotifier(this._uploadService)
    : super(
        const DriftBackupState(
          totalCount: 0,
          backupCount: 0,
          remainderCount: 0,
          processingCount: 0,
          enqueueCount: 0,
          enqueueTotalCount: 0,
          isCanceling: false,
          isSyncing: false,
          uploadItems: {},
          error: BackupError.none,
        ),
      ) {
    {
      _uploadService.taskStatusStream.listen(_handleTaskStatusUpdate);
      _uploadService.taskProgressStream.listen(_handleTaskProgressUpdate);
    }
  }

  final UploadService _uploadService;
  StreamSubscription<TaskStatusUpdate>? _statusSubscription;
  StreamSubscription<TaskProgressUpdate>? _progressSubscription;
  final _logger = Logger("DriftBackupNotifier");

  /// Remove upload item from state
  void _removeUploadItem(String taskId) {
    if (state.uploadItems.containsKey(taskId)) {
      final updatedItems = Map<String, DriftUploadStatus>.from(state.uploadItems);
      updatedItems.remove(taskId);
      state = state.copyWith(uploadItems: updatedItems);
    }
  }

  void _handleTaskStatusUpdate(TaskStatusUpdate update) {
    final taskId = update.task.taskId;

    switch (update.status) {
      case TaskStatus.complete:
        if (update.task.group == kBackupGroup) {
          if (update.responseStatusCode == 201) {
            final completedItem = state.uploadItems[taskId];
            final uploadedBytes = completedItem?.fileSize ?? 0;
            final newCompleted = state.sessionCompletedCount + 1;
            state = state.copyWith(
              backupCount: state.backupCount + 1,
              remainderCount: state.remainderCount - 1,
              sessionCompletedCount: newCompleted,
              sessionUploadedBytes: state.sessionUploadedBytes + uploadedBytes,
            );
            // Log progress milestones to avoid log spam: every 50 files or first/last
            if (newCompleted == 1 || newCompleted % 50 == 0 || newCompleted == state.sessionTotalCount) {
              _logger.info(
                "Upload progress: $newCompleted/${state.sessionTotalCount} done (${update.task.displayName})",
              );
            }
          } else {
            _logger.warning(
              "Upload finished with unexpected status ${update.responseStatusCode} for ${update.task.displayName}",
            );
          }
        }

        // Remove the completed task from the upload items
        if (state.uploadItems.containsKey(taskId)) {
          Future.delayed(const Duration(milliseconds: 1000), () {
            _removeUploadItem(taskId);
          });
        }

      case TaskStatus.failed:
        // Ignore retry errors to avoid confusing users
        if (update.exception?.description == 'Delayed or retried enqueue failed') {
          _removeUploadItem(taskId);
          return;
        }

        final currentItem = state.uploadItems[taskId];
        if (currentItem == null) {
          return;
        }

        String? error;
        final exception = update.exception;
        if (exception != null && exception is TaskHttpException) {
          final message = tryJsonDecode(exception.description)?['message'] as String?;
          if (message != null) {
            final responseCode = exception.httpResponseCode;
            error = "${exception.exceptionType}, response code $responseCode: $message";
          }
        }
        error ??= update.exception?.toString();

        state = state.copyWith(
          uploadItems: {
            ...state.uploadItems,
            taskId: currentItem.copyWith(isFailed: true, error: error),
          },
        );
        _logger.warning("Upload FAILED: ${update.task.displayName} → $error");
        break;

      case TaskStatus.canceled:
        _logger.info("Upload canceled: ${update.task.displayName}");
        _removeUploadItem(update.task.taskId);
        break;

      default:
        break;
    }
  }

  void _handleTaskProgressUpdate(TaskProgressUpdate update) {
    final taskId = update.task.taskId;
    final filename = update.task.displayName;
    final progress = update.progress;
    final currentItem = state.uploadItems[taskId];
    if (currentItem != null) {
      if (progress == kUploadStatusCanceled) {
        _removeUploadItem(update.task.taskId);
        return;
      }

      state = state.copyWith(
        uploadItems: {
          ...state.uploadItems,
          taskId: update.hasExpectedFileSize
              ? currentItem.copyWith(
                  progress: progress,
                  fileSize: update.expectedFileSize,
                  networkSpeedAsString: update.networkSpeedAsString,
                )
              : currentItem.copyWith(progress: progress),
        },
      );

      return;
    }

    state = state.copyWith(
      uploadItems: {
        ...state.uploadItems,
        taskId: DriftUploadStatus(
          taskId: taskId,
          filename: filename,
          progress: progress,
          fileSize: update.expectedFileSize,
          networkSpeedAsString: update.networkSpeedAsString,
        ),
      },
    );
  }

  Future<void> getBackupStatus(String userId) async {
    final counts = await _uploadService.getBackupCounts(userId);

    state = state.copyWith(
      totalCount: counts.total,
      backupCount: counts.total - counts.remainder,
      remainderCount: counts.remainder,
      processingCount: counts.processing,
    );
  }

  void updateError(BackupError error) async {
    state = state.copyWith(error: error);
  }

  void updateSyncing(bool isSyncing) async {
    state = state.copyWith(isSyncing: isSyncing);
  }

  Future<void> startBackup(String userId) async {
    _logger.info("startBackup: queuing candidates (remainder=${state.remainderCount})");
    state = state.copyWith(
      error: BackupError.none,
      sessionCompletedCount: 0,
      sessionTotalCount: state.remainderCount,
      sessionStartTime: DateTime.now(),
      sessionUploadedBytes: 0,
      isStartingBackup: true,
      prepCandidateTotal: 0,
      prepCandidateProcessed: 0,
    );
    try {
      await _uploadService.startBackup(userId, _updateEnqueueCount, _updatePrepProgress);
      _logger.info(
        "startBackup: enqueued=${state.enqueueCount}/${state.enqueueTotalCount} prepared=${state.prepCandidateProcessed}/${state.prepCandidateTotal}",
      );
    } finally {
      state = state.copyWith(isStartingBackup: false);
    }
  }

  void _updateEnqueueCount(EnqueueStatus status) {
    state = state.copyWith(enqueueCount: status.enqueueCount, enqueueTotalCount: status.totalCount);
  }

  void _updatePrepProgress(int processed, int total) {
    state = state.copyWith(prepCandidateProcessed: processed, prepCandidateTotal: total);
  }

  Future<void> cancel() async {
    dPrint(() => "Canceling backup tasks...");
    state = state.copyWith(enqueueCount: 0, enqueueTotalCount: 0, isCanceling: true, error: BackupError.none);

    final activeTaskCount = await _uploadService.cancelBackup();

    if (activeTaskCount > 0) {
      dPrint(() => "$activeTaskCount tasks left, continuing to cancel...");
      await cancel();
    } else {
      dPrint(() => "All tasks canceled successfully.");
      state = state.copyWith(
        isCanceling: false,
        uploadItems: {},
        sessionCompletedCount: 0,
        sessionTotalCount: 0,
        sessionUploadedBytes: 0,
      );
    }
  }

  Future<void> handleBackupResume(String userId) async {
    _logger.info("Resuming backup tasks...");
    state = state.copyWith(error: BackupError.none);
    final tasks = await _uploadService.getActiveTasks(kBackupGroup);
    _logger.info("Found ${tasks.length} tasks");

    if (tasks.isEmpty) {
      // Start a new backup queue
      _logger.info("Start a new backup queue");
      return startBackup(userId);
    }

    _logger.info("Tasks to resume: ${tasks.length}");
    return _uploadService.resumeBackup();
  }

  @override
  void dispose() {
    _statusSubscription?.cancel();
    _progressSubscription?.cancel();
    super.dispose();
  }
}

final driftBackupCandidateProvider = FutureProvider.autoDispose<List<LocalAsset>>((ref) async {
  final user = ref.watch(currentUserProvider);
  if (user == null) {
    return [];
  }

  return ref.read(backupRepositoryProvider).getCandidates(user.id, onlyHashed: false);
});

final driftCandidateBackupAlbumInfoProvider = FutureProvider.autoDispose.family<List<LocalAlbum>, String>((
  ref,
  assetId,
) {
  return ref.read(localAssetRepository).getSourceAlbums(assetId, backupSelection: BackupSelection.selected);
});
