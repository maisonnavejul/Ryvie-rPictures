import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:background_downloader/background_downloader.dart';
import 'package:cancellation_token_http/http.dart';
import 'package:flutter/foundation.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/constants/constants.dart';
import 'package:immich_mobile/domain/models/asset/base_asset.model.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/extensions/platform_extensions.dart';
import 'package:immich_mobile/infrastructure/repositories/backup.repository.dart';
import 'package:immich_mobile/infrastructure/repositories/local_asset.repository.dart';
import 'package:immich_mobile/infrastructure/repositories/storage.repository.dart';
import 'package:immich_mobile/providers/app_settings.provider.dart';
import 'package:immich_mobile/providers/backup/drift_backup.provider.dart';
import 'package:immich_mobile/providers/infrastructure/asset.provider.dart';
import 'package:immich_mobile/providers/infrastructure/storage.provider.dart';
import 'package:immich_mobile/repositories/asset_media.repository.dart';
import 'package:immich_mobile/repositories/upload.repository.dart';
import 'package:immich_mobile/services/api.service.dart';
import 'package:immich_mobile/services/app_settings.service.dart';
import 'package:immich_mobile/utils/debug_print.dart';
import 'package:logging/logging.dart';
import 'package:path/path.dart' as p;

final uploadServiceProvider = Provider((ref) {
  final service = UploadService(
    ref.watch(uploadRepositoryProvider),
    ref.watch(backupRepositoryProvider),
    ref.watch(storageRepositoryProvider),
    ref.watch(localAssetRepository),
    ref.watch(appSettingsServiceProvider),
    ref.watch(assetMediaRepositoryProvider),
  );

  ref.onDispose(service.dispose);
  return service;
});

class UploadService {
  UploadService(
    this._uploadRepository,
    this._backupRepository,
    this._storageRepository,
    this._localAssetRepository,
    this._appSettingsService,
    this._assetMediaRepository,
  ) {
    _uploadRepository.onUploadStatus = _onUploadCallback;
    _uploadRepository.onTaskProgress = _onTaskProgressCallback;
  }

  final UploadRepository _uploadRepository;
  final DriftBackupRepository _backupRepository;
  final StorageRepository _storageRepository;
  final DriftLocalAssetRepository _localAssetRepository;
  final AppSettingsService _appSettingsService;
  final AssetMediaRepository _assetMediaRepository;
  final Logger _logger = Logger('UploadService');

  final StreamController<TaskStatusUpdate> _taskStatusController = StreamController<TaskStatusUpdate>.broadcast();
  final StreamController<TaskProgressUpdate> _taskProgressController = StreamController<TaskProgressUpdate>.broadcast();

  Stream<TaskStatusUpdate> get taskStatusStream => _taskStatusController.stream;
  Stream<TaskProgressUpdate> get taskProgressStream => _taskProgressController.stream;

  bool shouldAbortQueuingTasks = false;

  void _onTaskProgressCallback(TaskProgressUpdate update) {
    if (!_taskProgressController.isClosed) {
      _taskProgressController.add(update);
    }
  }

  void _onUploadCallback(TaskStatusUpdate update) {
    if (!_taskStatusController.isClosed) {
      _taskStatusController.add(update);
    }
    _handleTaskStatusUpdate(update);
  }

  void dispose() {
    _taskStatusController.close();
    _taskProgressController.close();
  }

  Future<List<bool>> enqueueTasks(List<UploadTask> tasks) {
    return _uploadRepository.enqueueBackgroundAll(tasks);
  }

  Future<List<Task>> getActiveTasks(String group) {
    return _uploadRepository.getActiveTasks(group);
  }

  Future<({int total, int remainder, int processing})> getBackupCounts(String userId) {
    return _backupRepository.getAllCounts(userId);
  }

  Future<void> manualBackup(List<LocalAsset> localAssets) async {
    await _storageRepository.clearCache();
    List<UploadTask> tasks = [];
    for (final asset in localAssets) {
      final task = await getUploadTask(
        asset,
        group: kManualUploadGroup,
        priority: 1, // High priority after upload motion photo part
      );
      if (task != null) {
        tasks.add(task);
      }
    }

    if (tasks.isNotEmpty) {
      await enqueueTasks(tasks);
    }
  }

  /// Per Apple engineer Quinn ("the Eskimo") on the Apple Developer Forums:
  /// background URLSession can comfortably handle ~300 tasks; pushing 3000+ at
  /// once causes the system to throttle / suspend the session. On constate en
  /// pratique qu'avec >100 tâches en file ET du reuse de taskId (lors des
  /// cancel+re-enqueue), iOS commence à rejeter en cascade avec
  /// "Delayed or retried enqueue failed". On garde donc le cap bien en
  /// dessous pour laisser de la marge.
  static const int _kMaxQueuedTasks = 75;

  /// Asset IDs that failed at the upload-prep stage during this app session
  /// (typically iCloud-only originals whose binary content isn't on the device).
  /// They're hashed (so `getCandidates` returns them) but `getUploadTask` returns
  /// null because PhotoKit refuses to hand back the file. Caching them prevents
  /// the livelock where continueBackup fetches the same 13 candidates, all skip,
  /// the watchdog detects "no progress", triggers FULL RESTART, repeat forever.
  static final Set<String> _uploadPrepFailedIds = <String>{};

  /// Find backup candidates
  /// Build the upload tasks
  /// Enqueue the tasks
  Future<void> startBackup(
    String userId,
    void Function(EnqueueStatus status) onEnqueueTasks, [
    void Function(int processed, int total)? onPrepProgress,
    void Function(int unreachable)? onUnreachableUpdate,
  ]) async {
    final sw = Stopwatch()..start();
    await _storageRepository.clearCache();

    shouldAbortQueuingTasks = false;

    // De-duplicate against tasks already enqueued in FileDownloader
    // (so calling startBackup repeatedly while hashing produces new candidates is safe)
    final existingTasks = await _uploadRepository.getActiveTasks(kBackupGroup);
    final existingTaskIds = existingTasks.map((t) => t.taskId).toSet();

    // Cap the total in-flight queue size to avoid iOS background-session throttling.
    final remainingBudget = _kMaxQueuedTasks - existingTaskIds.length;
    if (remainingBudget <= 0) {
      _logger.info(
        "startBackup: queue already at cap (${existingTaskIds.length}/$_kMaxQueuedTasks) — "
        "skipping enqueue, will resume on next continueBackup tick",
      );
      return;
    }

    final allCandidates = await _backupRepository.getCandidates(userId);
    final filteredCandidates = allCandidates
        .where((c) => !existingTaskIds.contains(c.id))
        .where((c) => !_uploadPrepFailedIds.contains(c.id))
        .toList();
    final cachedFailedSkipped = allCandidates
        .where((c) => _uploadPrepFailedIds.contains(c.id))
        .length;
    // Surface the unreachable count to the UI (so it shows "Tout est sauvegardé"
    // when only iCloud-only files remain).
    onUnreachableUpdate?.call(cachedFailedSkipped);
    // Apply the queue cap — only enqueue up to `remainingBudget` new candidates this run.
    final candidates = filteredCandidates.take(remainingBudget).toList();

    if (candidates.isEmpty) {
      if (allCandidates.isEmpty) {
        _logger.info("startBackup: no candidates, everything already backed up");
      } else if (cachedFailedSkipped > 0) {
        _logger.info(
          "startBackup: nothing enqueueable — $cachedFailedSkipped candidates are iCloud-only "
          "(skipped from cache, will retry on next app launch)",
        );
      } else {
        _logger.info("startBackup: all ${allCandidates.length} candidates already enqueued");
      }
      return;
    }
    _logger.info(
      "startBackup: enqueueing ${candidates.length} of ${filteredCandidates.length} candidates "
      "(cap=$_kMaxQueuedTasks, already in queue=${existingTaskIds.length}, "
      "iCloud-skipped from cache=$cachedFailedSkipped). "
      "Remaining ${filteredCandidates.length - candidates.length} will be picked up after some uploads complete.",
    );

    // Immediately report total so the UI can show "Préparation 0 / N" right away
    onPrepProgress?.call(0, candidates.length);
    onEnqueueTasks(EnqueueStatus(enqueueCount: 0, totalCount: candidates.length));

    const batchSize = 500;
    const parallelPrepare = 10;
    int count = 0;
    int processed = 0;
    int skipped = 0;
    for (int i = 0; i < candidates.length; i += batchSize) {
      if (shouldAbortQueuingTasks) {
        _logger.warning("startBackup: aborted by user at $processed/${candidates.length}");
        break;
      }

      final batch = candidates.skip(i).take(batchSize).toList();
      final tasks = <UploadTask>[];

      // Prepare tasks in parallel sub-batches to speed up file resolution
      for (int j = 0; j < batch.length; j += parallelPrepare) {
        if (shouldAbortQueuingTasks) break;
        final subBatch = batch.skip(j).take(parallelPrepare).toList();
        final prepSw = Stopwatch()..start();
        final results = await Future.wait(subBatch.map(getUploadTask));
        prepSw.stop();
        // Log si l'extraction PhotoKit/iCloud d'un sous-batch est lente
        // (>5s pour 10 fichiers = ~500ms/fichier, typique d'un fetch iCloud).
        // Permet de voir pourquoi ça "bloque" lors de la préparation.
        if (prepSw.elapsedMilliseconds > 5000) {
          _logger.info(
            "startBackup: slow file extraction — ${prepSw.elapsedMilliseconds}ms for "
            "${subBatch.length} files (avg ${(prepSw.elapsedMilliseconds / subBatch.length).round()}ms/file) "
            "— probable iCloud fetch in progress",
          );
        }
        for (int k = 0; k < subBatch.length; k++) {
          if (results[k] == null) {
            _uploadPrepFailedIds.add(subBatch[k].id);
          } else {
            tasks.add(results[k]!);
          }
        }
        skipped += subBatch.length - results.whereType<UploadTask>().length;
        processed += subBatch.length;
        onPrepProgress?.call(processed, candidates.length);
      }

      if (tasks.isNotEmpty && !shouldAbortQueuingTasks) {
        count += tasks.length;
        try {
          await enqueueTasks(tasks);
          _logger.info("startBackup: enqueued ${tasks.length} (total: $count/${candidates.length})");
        } catch (e, st) {
          _logger.severe("startBackup: failed to enqueue batch of ${tasks.length}", e, st);
        }
        onEnqueueTasks(EnqueueStatus(enqueueCount: count, totalCount: candidates.length));
      }
    }
    sw.stop();
    _logger.info(
      "startBackup: done in ${sw.elapsed.inSeconds}s — enqueued=$count, skipped=$skipped (iCloud/missing), total candidates=${candidates.length}",
    );
  }

  Future<void> startBackupWithHttpClient(String userId, bool hasWifi, CancellationToken token) async {
    await _storageRepository.clearCache();

    shouldAbortQueuingTasks = false;

    final candidates = await _backupRepository.getCandidates(userId);
    if (candidates.isEmpty) {
      return;
    }

    const batchSize = 100;
    for (int i = 0; i < candidates.length; i += batchSize) {
      if (shouldAbortQueuingTasks || token.isCancelled) {
        break;
      }

      final batch = candidates.skip(i).take(batchSize).toList();
      List<UploadTaskWithFile> tasks = [];
      for (final asset in batch) {
        final requireWifi = _shouldRequireWiFi(asset);
        if (requireWifi && !hasWifi) {
          _logger.warning('Skipping upload for ${asset.id} because it requires WiFi');
          continue;
        }

        final task = await _getUploadTaskWithFile(asset);
        if (task != null) {
          tasks.add(task);
        }
      }

      if (tasks.isNotEmpty && !shouldAbortQueuingTasks) {
        await _uploadRepository.backupWithDartClient(tasks, token);
      }
    }
  }

  /// Cancel all ongoing uploads and reset the upload queue
  ///
  /// Return the number of left over tasks in the queue
  Future<int> cancelBackup() async {
    shouldAbortQueuingTasks = true;

    await _storageRepository.clearCache();
    await _uploadRepository.reset(kBackupGroup);
    await _uploadRepository.deleteDatabaseRecords(kBackupGroup);

    final activeTasks = await _uploadRepository.getActiveTasks(kBackupGroup);
    return activeTasks.length;
  }

  Future<void> resumeBackup() {
    return _uploadRepository.start();
  }

  /// Cancel a specific list of tasks (used to forcibly clear stuck uploads).
  Future<void> cancelTasks(List<String> taskIds) {
    return _uploadRepository.cancelTasksWithIds(taskIds);
  }

  /// Hard-reset the FileDownloader group: cancels every task in the group at the
  /// URLSession level and wipes the localstore records. Use this when iOS has
  /// frozen the NSURLSession slots — re-enqueueing afterwards is the closest
  /// in-process equivalent of restarting the app.
  ///
  /// Also stops any in-flight `startBackup` enqueue loop by setting the abort flag,
  /// AND vide le cache des fichiers marqués comme inaccessibles (iCloud). Sans
  /// ce reset, après un FULL RESTART, le système croit que tous les fichiers
  /// restants sont iCloud-only et n'essaie plus rien — alors qu'on vient
  /// justement de tout réinitialiser pour leur donner une nouvelle chance.
  Future<void> forceResetQueue() async {
    shouldAbortQueuingTasks = true;
    final cachedFailures = _uploadPrepFailedIds.length;
    _uploadPrepFailedIds.clear();
    if (cachedFailures > 0) {
      _logger.info('forceResetQueue: cleared $cachedFailures cached iCloud/missing failures so they get retried');
    }
    await _uploadRepository.reset(kBackupGroup);
    await _uploadRepository.deleteDatabaseRecords(kBackupGroup);
  }

  void _handleTaskStatusUpdate(TaskStatusUpdate update) async {
    switch (update.status) {
      case TaskStatus.complete:
        unawaited(_handleLivePhoto(update));

        if (CurrentPlatform.isIOS) {
          try {
            final path = await update.task.filePath();
            await File(path).delete();
          } catch (e) {
            _logger.fine('Temp file already deleted for iOS: $e');
          }
        }

        // Delete the task record from FileDownloader's localstore to keep the
        // task records directory small. Otherwise, with thousands of completed
        // tasks, iOS runs out of file descriptors (EMFILE) when scanning records.
        unawaited(
          _uploadRepository.deleteDatabaseRecord(update.task.taskId).catchError((e) {
            _logger.fine('Could not delete task record: $e');
          }),
        );
        break;

      case TaskStatus.failed:
        // Log iOS-level details — HTTP code + exception type — pour comprendre
        // si c'est un timeout NSURLSession, un 401, un 5xx serveur, etc.
        final exc = update.exception;
        final httpCode = (exc is TaskHttpException) ? exc.httpResponseCode : null;
        final excType = exc?.exceptionType ?? 'unknown';
        _logger.warning(
          "iOS task FAILED: ${update.task.displayName} — "
          "type=$excType${httpCode != null ? ', HTTP=$httpCode' : ''}, "
          "desc=${exc?.description ?? 'n/a'}",
        );
        unawaited(
          _uploadRepository.deleteDatabaseRecord(update.task.taskId).catchError((e) {
            _logger.fine('Could not delete task record: $e');
          }),
        );
        break;

      case TaskStatus.canceled:
        _logger.info("iOS task CANCELED: ${update.task.displayName}");
        unawaited(
          _uploadRepository.deleteDatabaseRecord(update.task.taskId).catchError((e) {
            _logger.fine('Could not delete task record: $e');
          }),
        );
        break;

      default:
        break;
    }
  }

  Future<void> _handleLivePhoto(TaskStatusUpdate update) async {
    try {
      if (update.task.metaData.isEmpty || update.task.metaData == '') {
        return;
      }

      final metadata = UploadTaskMetadata.fromJson(update.task.metaData);
      if (!metadata.isLivePhotos) {
        return;
      }

      if (update.responseBody == null || update.responseBody!.isEmpty) {
        return;
      }
      final response = jsonDecode(update.responseBody!);

      final localAsset = await _localAssetRepository.getById(metadata.localAssetId);
      if (localAsset == null) {
        return;
      }

      final uploadTask = await getLivePhotoUploadTask(localAsset, response['id'] as String);

      if (uploadTask == null) {
        return;
      }

      await enqueueTasks([uploadTask]);
    } catch (error, stackTrace) {
      dPrint(() => "Error handling live photo upload task: $error $stackTrace");
    }
  }

  Future<UploadTaskWithFile?> _getUploadTaskWithFile(LocalAsset asset) async {
    final entity = await _storageRepository.getAssetEntityForAsset(asset);
    if (entity == null) {
      return null;
    }

    final file = await _storageRepository.getFileForAsset(asset.id);
    if (file == null) {
      return null;
    }

    final originalFileName = entity.isLivePhoto ? p.setExtension(asset.name, p.extension(file.path)) : asset.name;

    String metadata = UploadTaskMetadata(
      localAssetId: asset.id,
      isLivePhotos: entity.isLivePhoto,
      livePhotoVideoId: '',
    ).toJson();

    return UploadTaskWithFile(
      file: file,
      task: await buildUploadTask(
        file,
        createdAt: asset.createdAt,
        modifiedAt: asset.updatedAt,
        originalFileName: originalFileName,
        deviceAssetId: asset.id,
        metadata: metadata,
        group: "group",
        priority: 0,
        isFavorite: asset.isFavorite,
        requiresWiFi: false,
      ),
    );
  }

  @visibleForTesting
  Future<UploadTask?> getUploadTask(LocalAsset asset, {String group = kBackupGroup, int? priority}) async {
    final entity = await _storageRepository.getAssetEntityForAsset(asset);
    if (entity == null) {
      return null;
    }

    // Si le user a activé "ignorer les photos iCloud", on évite carrément
    // de tenter l'extraction (qui déclenche un fetch iCloud lent puis échoue).
    // On check `isLocallyAvailable` avant tout — c'est très rapide (lecture
    // d'attribut PhotoKit).
    if (Platform.isIOS && _appSettingsService.getSetting(AppSettingsEnum.ignoreIcloudAssets)) {
      try {
        final available = await entity.isLocallyAvailable(isOrigin: true).timeout(const Duration(seconds: 1));
        if (!available) {
          // Fichier iCloud uniquement → skip immédiatement, le cache
          // _uploadPrepFailedIds le retiendra pour éviter les re-tries.
          return null;
        }
      } catch (_) {
        // En cas d'erreur de check, on laisse passer pour fallback sur
        // l'ancien comportement (3s timeout).
      }
    }

    File? file;

    /// iOS LivePhoto has two files: a photo and a video.
    /// They are uploaded separately, with video file being upload first, then returned with the assetId
    /// The assetId is then used as a metadata for the photo file upload task.
    ///
    /// We implement two separate upload groups for this, the normal one for the video file
    /// and the higher priority group for the photo file because the video file is already uploaded.
    ///
    /// The cancel operation will only cancel the video group (normal group), the photo group will not
    /// be touched, as the video file is already uploaded.

    if (entity.isLivePhoto) {
      file = await _storageRepository.getMotionFileForAsset(asset);
    } else {
      file = await _storageRepository.getFileForAsset(asset.id);
    }

    if (file == null) {
      return null;
    }

    final fileName = await _assetMediaRepository.getOriginalFilename(asset.id) ?? asset.name;
    final originalFileName = entity.isLivePhoto ? p.setExtension(fileName, p.extension(file.path)) : fileName;

    String metadata = UploadTaskMetadata(
      localAssetId: asset.id,
      isLivePhotos: entity.isLivePhoto,
      livePhotoVideoId: '',
    ).toJson();

    final requiresWiFi = _shouldRequireWiFi(asset);

    return buildUploadTask(
      file,
      createdAt: asset.createdAt,
      modifiedAt: asset.updatedAt,
      originalFileName: originalFileName,
      deviceAssetId: asset.id,
      metadata: metadata,
      group: group,
      priority: priority,
      isFavorite: asset.isFavorite,
      requiresWiFi: requiresWiFi,
    );
  }

  @visibleForTesting
  Future<UploadTask?> getLivePhotoUploadTask(LocalAsset asset, String livePhotoVideoId) async {
    final entity = await _storageRepository.getAssetEntityForAsset(asset);
    if (entity == null) {
      return null;
    }

    final file = await _storageRepository.getFileForAsset(asset.id);
    if (file == null) {
      return null;
    }

    final fields = {'livePhotoVideoId': livePhotoVideoId};

    final requiresWiFi = _shouldRequireWiFi(asset);
    final originalFileName = await _assetMediaRepository.getOriginalFilename(asset.id) ?? asset.name;

    return buildUploadTask(
      file,
      createdAt: asset.createdAt,
      modifiedAt: asset.updatedAt,
      originalFileName: originalFileName,
      deviceAssetId: asset.id,
      fields: fields,
      group: kBackupLivePhotoGroup,
      priority: 0, // Highest priority to get upload immediately
      isFavorite: asset.isFavorite,
      requiresWiFi: requiresWiFi,
    );
  }

  bool _shouldRequireWiFi(LocalAsset asset) {
    bool requiresWiFi = true;

    if (asset.isVideo && _appSettingsService.getSetting(AppSettingsEnum.useCellularForUploadVideos)) {
      requiresWiFi = false;
    } else if (!asset.isVideo && _appSettingsService.getSetting(AppSettingsEnum.useCellularForUploadPhotos)) {
      requiresWiFi = false;
    }

    return requiresWiFi;
  }

  Future<UploadTask> buildUploadTask(
    File file, {
    required String group,
    required DateTime createdAt,
    required DateTime modifiedAt,
    Map<String, String>? fields,
    String? originalFileName,
    String? deviceAssetId,
    String? metadata,
    int? priority,
    bool? isFavorite,
    bool requiresWiFi = true,
  }) async {
    final serverEndpoint = Store.get(StoreKey.serverEndpoint);
    final url = Uri.parse('$serverEndpoint/assets').toString();
    final headers = ApiService.getRequestHeaders();
    final deviceId = Store.get(StoreKey.deviceId);
    final (baseDirectory, directory, filename) = await Task.split(filePath: file.path);
    final fieldsMap = {
      'filename': originalFileName ?? filename,
      'deviceAssetId': deviceAssetId ?? '',
      'deviceId': deviceId,
      'fileCreatedAt': createdAt.toUtc().toIso8601String(),
      'fileModifiedAt': modifiedAt.toUtc().toIso8601String(),
      'isFavorite': isFavorite?.toString() ?? 'false',
      'duration': '0',
      if (fields != null) ...fields,
    };

    return UploadTask(
      taskId: deviceAssetId,
      displayName: originalFileName ?? filename,
      httpRequestMethod: 'POST',
      url: url,
      headers: headers,
      filename: filename,
      fields: fieldsMap,
      baseDirectory: baseDirectory,
      directory: directory,
      fileField: 'assetData',
      metaData: metadata ?? '',
      group: group,
      requiresWiFi: requiresWiFi,
      priority: priority ?? 5,
      updates: Updates.statusAndProgress,
      retries: 3,
    );
  }
}

class UploadTaskMetadata {
  final String localAssetId;
  final bool isLivePhotos;
  final String livePhotoVideoId;

  const UploadTaskMetadata({required this.localAssetId, required this.isLivePhotos, required this.livePhotoVideoId});

  UploadTaskMetadata copyWith({String? localAssetId, bool? isLivePhotos, String? livePhotoVideoId}) {
    return UploadTaskMetadata(
      localAssetId: localAssetId ?? this.localAssetId,
      isLivePhotos: isLivePhotos ?? this.isLivePhotos,
      livePhotoVideoId: livePhotoVideoId ?? this.livePhotoVideoId,
    );
  }

  Map<String, dynamic> toMap() {
    return <String, dynamic>{
      'localAssetId': localAssetId,
      'isLivePhotos': isLivePhotos,
      'livePhotoVideoId': livePhotoVideoId,
    };
  }

  factory UploadTaskMetadata.fromMap(Map<String, dynamic> map) {
    return UploadTaskMetadata(
      localAssetId: map['localAssetId'] as String,
      isLivePhotos: map['isLivePhotos'] as bool,
      livePhotoVideoId: map['livePhotoVideoId'] as String,
    );
  }

  String toJson() => json.encode(toMap());

  factory UploadTaskMetadata.fromJson(String source) =>
      UploadTaskMetadata.fromMap(json.decode(source) as Map<String, dynamic>);

  @override
  String toString() =>
      'UploadTaskMetadata(localAssetId: $localAssetId, isLivePhotos: $isLivePhotos, livePhotoVideoId: $livePhotoVideoId)';

  @override
  bool operator ==(covariant UploadTaskMetadata other) {
    if (identical(this, other)) return true;

    return other.localAssetId == localAssetId &&
        other.isLivePhotos == isLivePhotos &&
        other.livePhotoVideoId == livePhotoVideoId;
  }

  @override
  int get hashCode => localAssetId.hashCode ^ isLivePhotos.hashCode ^ livePhotoVideoId.hashCode;
}
