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
  final double networkSpeed; // MB/s, -1.0 if unknown
  final bool? isFailed;
  final String? error;
  /// Timestamp du premier progress event reçu pour ce task. Sert au watchdog
  /// pour identifier les tasks "vieux et bloqués" et les logger dans le
  /// health-check.
  final DateTime? firstSeenAt;
  /// Dernier progress event où `progress` ou les bytes ont augmenté.
  /// Si on stagne, on peut détecter quel task spécifiquement est bloqué.
  final DateTime? lastProgressAt;

  const DriftUploadStatus({
    required this.taskId,
    required this.filename,
    required this.progress,
    required this.fileSize,
    required this.networkSpeedAsString,
    this.networkSpeed = -1.0,
    this.isFailed,
    this.error,
    this.firstSeenAt,
    this.lastProgressAt,
  });

  DriftUploadStatus copyWith({
    String? taskId,
    String? filename,
    double? progress,
    int? fileSize,
    String? networkSpeedAsString,
    double? networkSpeed,
    bool? isFailed,
    String? error,
    DateTime? firstSeenAt,
    DateTime? lastProgressAt,
  }) {
    return DriftUploadStatus(
      taskId: taskId ?? this.taskId,
      filename: filename ?? this.filename,
      progress: progress ?? this.progress,
      fileSize: fileSize ?? this.fileSize,
      networkSpeedAsString: networkSpeedAsString ?? this.networkSpeedAsString,
      networkSpeed: networkSpeed ?? this.networkSpeed,
      isFailed: isFailed ?? this.isFailed,
      error: error ?? this.error,
      firstSeenAt: firstSeenAt ?? this.firstSeenAt,
      lastProgressAt: lastProgressAt ?? this.lastProgressAt,
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

  /// Valeur de [backupCount] (vérité DB) au démarrage de la session courante.
  /// La progression affichée est dérivée de la DB par rapport à cette base :
  ///   X (fait cette session) = backupCount - sessionBaselineBackupCount
  /// Ainsi un fichier n'est compté "fait" que lorsque le serveur l'a réellement
  /// confirmé (entrée dans remote_asset_entity), jamais de façon optimiste — le
  /// compteur ne recule donc plus au redémarrage.
  final int sessionBaselineBackupCount;
  final DateTime? sessionStartTime;
  final int sessionUploadedBytes;
  final bool isStartingBackup;
  final int prepCandidateTotal;
  final int prepCandidateProcessed;
  /// Files that cannot be uploaded right now (e.g. iCloud-only originals that
  /// PhotoKit refuses to hand back). Surfaced to the UI so we can exclude them
  /// from "remaining" and show "Tout est sauvegardé" once all reachable files
  /// are done.
  final int unreachableCount;

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
    this.sessionBaselineBackupCount = 0,
    this.sessionStartTime,
    this.sessionUploadedBytes = 0,
    this.isStartingBackup = false,
    this.prepCandidateTotal = 0,
    this.prepCandidateProcessed = 0,
    this.recentSpeedMBs = 0,
    this.unreachableCount = 0,
  });

  /// Remainder count minus files we already know are unreachable (e.g. iCloud).
  /// This is what the UI should use to decide if there's still "work" to do.
  int get effectiveRemainderCount {
    final eff = remainderCount - unreachableCount;
    return eff > 0 ? eff : 0;
  }

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
    int? sessionBaselineBackupCount,
    DateTime? sessionStartTime,
    int? sessionUploadedBytes,
    bool? isStartingBackup,
    int? prepCandidateTotal,
    int? prepCandidateProcessed,
    double? recentSpeedMBs,
    int? unreachableCount,
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
      sessionBaselineBackupCount: sessionBaselineBackupCount ?? this.sessionBaselineBackupCount,
      sessionStartTime: sessionStartTime ?? this.sessionStartTime,
      sessionUploadedBytes: sessionUploadedBytes ?? this.sessionUploadedBytes,
      isStartingBackup: isStartingBackup ?? this.isStartingBackup,
      prepCandidateTotal: prepCandidateTotal ?? this.prepCandidateTotal,
      prepCandidateProcessed: prepCandidateProcessed ?? this.prepCandidateProcessed,
      recentSpeedMBs: recentSpeedMBs ?? this.recentSpeedMBs,
      unreachableCount: unreachableCount ?? this.unreachableCount,
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

  /// Progression "Upload en cours X / Y", entièrement dérivée de la vérité DB.
  ///
  /// Garantie : quand `X == Y`, tous les fichiers atteignables de la session
  /// sont réellement confirmés par le serveur. Les iCloud-only injoignables
  /// (`unreachableCount`) sont exclus de Y, comme la card "Restant".
  ///
  /// Fichiers réellement confirmés par le serveur DEPUIS le début de la session
  /// (jamais optimiste). C'est le "X" de "X / Y".
  int get sessionCompleted {
    final done = backupCount - sessionBaselineBackupCount;
    return done > 0 ? done : 0;
  }

  int get displayedSessionTotal {
    // Y = tout ce que la session doit faire = déjà confirmé cette session
    // + ce qui reste réellement (hors iCloud injoignables). Comme X et Y
    // dérivent du MÊME instantané DB, ils bougent en phase : pas de gonflement
    // pendant l'upload, pas de recul au redémarrage.
    final total = totalCount - sessionBaselineBackupCount - unreachableCount;
    return total > 0 ? total : 0;
  }

  double get sessionProgress {
    final total = displayedSessionTotal;
    if (total == 0) return 0;
    final p = sessionCompleted / total;
    return p > 1 ? 1 : p;
  }

  Duration? get estimatedTimeRemaining {
    if (sessionStartTime == null || sessionCompleted == 0) return null;
    final elapsed = DateTime.now().difference(sessionStartTime!);
    final remaining = displayedSessionTotal - sessionCompleted;
    if (remaining <= 0) return Duration.zero;
    final msPerFile = elapsed.inMilliseconds / sessionCompleted;
    return Duration(milliseconds: (msPerFile * remaining).round());
  }

  /// Rolling 2-minute upload speed in MB/s.
  /// Computed in the notifier from a sliding window of (timestamp, bytes) samples,
  /// exposed via state copies. Returns 0 if no recent samples or window too short.
  double get sessionAverageSpeedMBs => recentSpeedMBs;

  /// Recent speed sample (computed by the notifier from a rolling window)
  final double recentSpeedMBs;

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
        other.sessionBaselineBackupCount == sessionBaselineBackupCount &&
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
        sessionBaselineBackupCount.hashCode ^
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

  Timer? _stalledWatchdog;
  Timer? _retrySweeper;
  Timer? _queueKicker;
  String? _currentUserId;

  // Health-check snapshot from the previous tick — used to detect real progress.
  int _lastCheckCompletedCount = 0;
  int _lastCheckUploadedBytes = 0;
  // Quand on a basculé en état "all tasks in waiting_retry". Sert à détecter
  // qu'on stagne dans cet état trop longtemps (iOS/plugin coincé) et à
  // forcer un FULL RESTART. null = on n'est pas dans cet état.
  DateTime? _allRetrySince;
  // Number of consecutive 60s ticks where uploads stalled without recovery.
  int _stalledTicks = 0;

  // Rolling 2-minute window of (timestamp, cumulative bytes) samples used to
  // compute a recent speed indicator. The user wants speed reflecting the LAST
  // 2 minutes, not the entire session average.
  static const Duration _speedWindow = Duration(minutes: 2);
  final List<(DateTime, int)> _byteSamples = [];

  // Throttle the low-watermark refill so we don't fire continueBackup on every
  // single completion (which would spam getCandidates queries on the DB).
  DateTime _lastTopUpAt = DateTime.fromMillisecondsSinceEpoch(0);

  /// True quand le hashing tourne. On évite alors d'enqueuer des fichiers
  /// (le compte n'est pas encore fiable, et ça ralentit le hashing).
  /// Trigger continueBackup proactively when the in-flight queue gets low,
  /// keeping iOS fed with fresh tasks at all times. Le seuil et le throttle
  /// sont ajustés pour que la queue ne se vide jamais à 0 (sinon l'UI flicke
  /// entre "Upload en cours" et "Préparation"). La prep PhotoKit prenant
  /// quelques secondes, on top-up bien avant que la queue ne soit drainée.
  void _maybeTopUpQueue() {
    // Watermark à 20 sur cap=25 : top-up dès qu'on a 5 slots libres.
    // Évite à la fois les trous (queue=0 entre 2 batches) et la sur-saturation
    // d'iOS.
    if (state.uploadItems.length >= 20) return;
    if (state.effectiveRemainderCount <= 0) return;
    if (state.isStartingBackup) return;
    if (_currentUserId == null) return;
    final now = DateTime.now();
    // Throttle court : 2s entre top-ups (suffit pour que la prep PhotoKit
    // ait le temps de finir avant qu'on en relance une).
    if (now.difference(_lastTopUpAt).inSeconds < 2) return;
    _lastTopUpAt = now;
    _logger.info(
      "Low watermark: queue=${state.uploadItems.length}, remaining=${state.remainderCount} — proactively topping up",
    );
    unawaited(continueBackup(_currentUserId!));
  }

  void _pushByteSample(int totalBytes) {
    final now = DateTime.now();
    _byteSamples.add((now, totalBytes));
    // Drop samples outside the window
    final cutoff = now.subtract(_speedWindow);
    _byteSamples.removeWhere((s) => s.$1.isBefore(cutoff));
    // Compute and publish recent speed
    if (_byteSamples.length < 2) {
      if (state.recentSpeedMBs != 0) {
        state = state.copyWith(recentSpeedMBs: 0);
      }
      return;
    }
    final first = _byteSamples.first;
    final last = _byteSamples.last;
    final dtSec = last.$1.difference(first.$1).inMilliseconds / 1000.0;
    if (dtSec <= 0.1) return;
    final speed = ((last.$2 - first.$2) / dtSec) / (1024 * 1024);
    state = state.copyWith(recentSpeedMBs: speed > 0 ? speed : 0);
  }

  /// SAFETY NET — historiquement ce sweeper cancellait les WAITING_RETRY
  /// après 15s. Maintenant on cancel directement dans `_handleTaskStatusUpdate`
  /// (case waitingToRetry) dès le premier event, donc ce sweeper ne devrait
  /// quasiment jamais avoir de boulot. On le laisse comme filet de sécurité
  /// au cas où un task entre en WAITING_RETRY sans déclencher notre handler.
  ///
  /// Si >50% des tâches sont en retry, on skip (système saturé).
  Future<void> _cancelStuckRetries() async {
    if (state.uploadItems.isEmpty) return;

    final waitingRetry = state.uploadItems.values
        .where((item) => item.progress == kUploadStatusWaitingToRetry)
        .length;
    final ratio = waitingRetry / state.uploadItems.length;
    if (ratio > 0.5 && state.uploadItems.length >= 10) {
      _logger.warning(
        "Retry sweeper: SKIP — too many tasks in retry "
        "($waitingRetry/${state.uploadItems.length} = ${(ratio * 100).toStringAsFixed(0)}%) "
        "— iOS likely refusing enqueues, letting it settle",
      );
      return;
    }

    const stuckRetryThreshold = Duration(seconds: 15);
    final now = DateTime.now();
    final stuckIds = <String>[];
    for (final item in state.uploadItems.values) {
      if (item.progress != kUploadStatusWaitingToRetry) continue;
      if (item.firstSeenAt == null) continue;
      if (now.difference(item.firstSeenAt!) > stuckRetryThreshold) {
        stuckIds.add(item.taskId);
      }
    }
    if (stuckIds.isEmpty) return;
    _logger.info(
      "Retry sweeper: cancelling ${stuckIds.length} task(s) stuck in WAITING_RETRY >15s — "
      "they will be re-enqueued fresh (no iOS back-off)",
    );
    try {
      await _uploadService.cancelTasks(stuckIds);
    } catch (e, st) {
      _logger.warning("Retry sweeper: failed to cancel: $e", e, st);
    }
    final cleaned = Map<String, DriftUploadStatus>.from(state.uploadItems)
      ..removeWhere((id, _) => stuckIds.contains(id));
    state = state.copyWith(uploadItems: cleaned);
    // Attendre 5s avant de top-up : iOS a besoin de libérer ses ressources
    // (fichiers temporaires, sockets) avant qu'on re-enqueue. Sans cette
    // pause, on re-tape immédiatement et iOS re-rejette en cascade.
    await Future.delayed(const Duration(seconds: 5));
    // Force le top-up (bypass le throttle 15s).
    _lastTopUpAt = DateTime.fromMillisecondsSinceEpoch(0);
    _maybeTopUpQueue();
  }

  /// Health check that runs every 60 seconds and ALWAYS logs an OK / NOT OK line
  /// at INFO level so the upload state is visible in the journal. When uploads
  /// are stalled, it triggers progressive recovery (kick → full restart).
  /// Plus un timer 15s dédié à la cancellation rapide des tâches stuck en
  /// `WAITING_RETRY` — ça force un retry frais (iOS traite comme nouveau task)
  /// au lieu d'attendre son back-off exponentiel (30s/60s/120s).
  void _ensureWatchdogRunning() {
    if (_stalledWatchdog != null) return;
    // Capture baseline so the first tick has something to compare to.
    _lastCheckCompletedCount = state.sessionCompletedCount;
    _lastCheckUploadedBytes = state.sessionUploadedBytes;
    _stalledTicks = 0;
    _stalledWatchdog = Timer.periodic(const Duration(seconds: 60), (_) => _runHealthCheck());
    _retrySweeper = Timer.periodic(const Duration(seconds: 15), (_) => _cancelStuckRetries());
    // Kick périodique du queue refill toutes les 10s, INDÉPENDAMMENT de quelle
    // page est affichée. Sans ça, iOS peut ralentir les uploads quand l'UI
    // n'est pas active sur la page de sauvegarde — le user a l'impression que
    // ça n'avance que quand il regarde la page.
    _queueKicker = Timer.periodic(const Duration(seconds: 10), (_) => _kickQueue());
    _logger.info("Backup health-check started (60s interval) + queue kicker (10s)");
  }

  /// Kick périodique : force un top-up si la queue est sous le watermark,
  /// même si aucun event de completion n'est arrivé récemment. Ça garantit
  /// que les uploads continuent peu importe la page affichée.
  void _kickQueue() {
    if (state.uploadItems.length >= 20) return;
    if (state.effectiveRemainderCount <= 0) return;
    if (state.isStartingBackup) return;
    if (_currentUserId == null) return;
    // Bypass le throttle de _maybeTopUpQueue — ce kicker EST le mécanisme
    // périodique, il a déjà sa propre cadence (10s).
    _lastTopUpAt = DateTime.fromMillisecondsSinceEpoch(0);
    _maybeTopUpQueue();
  }

  Future<void> _runHealthCheck() async {
    // Nothing left to do (no uploads + no reachable remainder) — stop the timer.
    if (state.uploadItems.isEmpty && state.effectiveRemainderCount == 0 && !state.isStartingBackup) {
      if (state.unreachableCount > 0) {
        _logger.info(
          "Backup health-check: complete (${state.unreachableCount} files unreachable / iCloud, not retried) — stopping watchdog",
        );
      } else {
        _logger.info("Backup health-check: idle (everything backed up) — stopping watchdog");
      }
      _stalledWatchdog?.cancel();
      _stalledWatchdog = null;
      _retrySweeper?.cancel();
      _retrySweeper = null;
      _queueKicker?.cancel();
      _queueKicker = null;
      _stalledTicks = 0;
      return;
    }

    final completedDelta = state.sessionCompletedCount - _lastCheckCompletedCount;
    final bytesDelta = state.sessionUploadedBytes - _lastCheckUploadedBytes;
    _lastCheckCompletedCount = state.sessionCompletedCount;
    _lastCheckUploadedBytes = state.sessionUploadedBytes;
    final mbDelta = bytesDelta / (1024 * 1024);

    final enqStatus = state.isStartingBackup ? " [enqueueing]" : "";
    // Breakdown des tâches actives : running (progress 0..1) vs waiting_retry
    // (iOS back-off, progress=-4) vs failed (progress=-1). Permet de voir en
    // une ligne si le souci est iOS (waiting_retry élevé) ou autre.
    int running = 0;
    int waitingRetry = 0;
    int failedShown = 0;
    for (final item in state.uploadItems.values) {
      if (item.isFailed == true) {
        failedShown++;
      } else if (item.progress == kUploadStatusWaitingToRetry) {
        waitingRetry++;
      } else {
        running++;
      }
    }
    final breakdown = "active=${state.uploadItems.length}"
        "[run=$running,retry=$waitingRetry${failedShown > 0 ? ",fail=$failedShown" : ""}]";
    final snapshot = "$breakdown "
        "remaining=${state.remainderCount} "
        "session=${state.sessionCompletedCount}/${state.displayedSessionTotal}$enqStatus";

    // Real progress detected — uploads are moving forward.
    // We don't skip the check when enqueueing: uploads and enqueueing run in
    // parallel, and enqueueing 7000 candidates can take 10+ minutes during which
    // uploads can genuinely stall. Only sessionCompletedCount / bytes moving counts.
    if (completedDelta > 0 || bytesDelta > 0) {
      _stalledTicks = 0;
      _logger.info(
        "Backup health-check: OK (+$completedDelta files / +${mbDelta.toStringAsFixed(1)} MB in 60s, $snapshot)",
      );
      return;
    }

    // No upload progress in 60s.
    // Special case: brand-new session with no uploads yet (uploadItems empty AND
    // isStartingBackup true) — we're still building the queue, give it more time.
    if (state.uploadItems.isEmpty && state.isStartingBackup && state.sessionCompletedCount == 0) {
      _logger.info("Backup health-check: OK (warming up, $snapshot)");
      return;
    }

    // Special case: queue is empty AND there's nothing to do (no active uploads,
    // no fresh candidates being added). This happens when remaining files are
    // all iCloud-only and have been cached as "failed". Not a real stall.
    if (state.uploadItems.isEmpty && state.enqueueCount == state.enqueueTotalCount && state.remainderCount > 0) {
      _logger.info(
        "Backup health-check: OK (idle — ${state.remainderCount} files remain but appear non-uploadable, likely iCloud-only, $snapshot)",
      );
      _stalledTicks = 0;
      return;
    }

    // Cancellation rapide des stuck retries est gérée par _cancelStuckRetries
    // (timer 15s). Ici, si TOUTES les tâches actives restantes sont en
    // `waitingToRetry`, on tolère jusqu'à 2 minutes (iOS peut faire son
    // back-off). Au-delà, c'est qu'iOS/plugin est coincé (erreur
    // "Delayed or retried enqueue failed" qui se répète à l'infini) — on
    // force FULL RESTART pour repartir sur une session propre.
    final allWaitingRetry = state.uploadItems.values.every(
      (item) => item.progress == kUploadStatusWaitingToRetry,
    );
    if (allWaitingRetry && state.uploadItems.isNotEmpty) {
      _allRetrySince ??= DateTime.now();
      final stuckFor = DateTime.now().difference(_allRetrySince!);
      const allRetryRecoveryThreshold = Duration(minutes: 2);
      if (stuckFor < allRetryRecoveryThreshold) {
        _logger.info(
          "Backup health-check: OK (all ${state.uploadItems.length} tasks in iOS retry "
          "since ${stuckFor.inSeconds}s — FULL RESTART in ${allRetryRecoveryThreshold.inSeconds - stuckFor.inSeconds}s if no recovery, $snapshot)",
        );
        _stalledTicks = 0;
        return;
      }
      // Stagnation trop longue → on force la récupération via FULL RESTART.
      _logger.warning(
        "Backup health-check: STUCK ${stuckFor.inSeconds}s in all-retry state — "
        "iOS/plugin jammed, triggering FULL RESTART",
      );
      _allRetrySince = null;
      _stalledTicks = 2; // saute directement à l'étape FULL RESTART (tick 2+)
      // fall through au bloc "stalled recovery" ci-dessous
    } else {
      // On n'est plus en état "all retry" → reset le marker.
      _allRetrySince = null;
    }

    // Suspected stall — count it and trigger recovery.
    _stalledTicks++;
    final waitingRetryCount = state.uploadItems.values
        .where((item) => item.progress == kUploadStatusWaitingToRetry)
        .length;
    _logger.info(
      "Backup health-check: NOT OK — no progress in 60s "
      "(stalled $_stalledTicks tick(s), waiting_retry=$waitingRetryCount, $snapshot)",
    );

    // Dump détaillé des tâches actives : âge depuis 1er progress, date du
    // dernier vrai progress, % actuel, vitesse, taille. Permet de voir
    // EXACTEMENT quels fichiers sont bloqués et depuis combien de temps.
    if (state.uploadItems.isNotEmpty) {
      final now = DateTime.now();
      final entries = state.uploadItems.values.toList()
        ..sort((a, b) => (a.firstSeenAt ?? now).compareTo(b.firstSeenAt ?? now));
      _logger.info("Backup health-check: ${entries.length} active task(s) — details:");
      for (final item in entries.take(20)) {
        final age = item.firstSeenAt != null
            ? '${now.difference(item.firstSeenAt!).inSeconds}s'
            : '?';
        final sinceProgress = item.lastProgressAt != null
            ? '${now.difference(item.lastProgressAt!).inSeconds}s'
            : '?';
        final sizeMb = (item.fileSize / (1024 * 1024)).toStringAsFixed(1);
        final String pctLabel;
        if (item.progress == kUploadStatusWaitingToRetry) {
          pctLabel = 'WAITING_RETRY';
        } else if (item.progress == kUploadStatusFailed) {
          pctLabel = 'FAILED';
        } else if (item.progress == kUploadStatusCanceled) {
          pctLabel = 'CANCELED';
        } else {
          pctLabel = '${(item.progress * 100).toStringAsFixed(0)}%';
        }
        final speed = item.networkSpeed > 0
            ? '${item.networkSpeed.toStringAsFixed(2)} MB/s'
            : 'idle';
        _logger.info(
          "  • ${item.filename} [$pctLabel] size=${sizeMb}MB age=$age noProgress=$sinceProgress speed=$speed",
        );
      }
      if (entries.length > 20) {
        _logger.info("  ... and ${entries.length - 20} more");
      }
    }

    // Progressive recovery — DON'T short-circuit on isStartingBackup because a
    // large enqueue can run for 10+ minutes while uploads are stuck:
    //  - tick 1 (60s):  cheap kick — FileDownloader.start() wakes NSURLSession if just paused
    //  - tick 2 (120s): FULL RESTART — mimics what closing & reopening the app does.
    //                   Resets everything in iOS, then re-enqueues fresh — KEEPING the
    //                   session counters (X files / Y MB) visible so the user doesn't lose
    //                   sight of what was already done.
    try {
      if (_stalledTicks == 1) {
        _logger.info("Backup health-check: kicking FileDownloader.start()");
        await _uploadService.resumeBackup();
        return;
      }

      // Tick 2+ → FULL RESTART
      _logger.warning(
        "Backup health-check: FULL RESTART (tick $_stalledTicks) — equivalent to closing/reopening the app, "
        "but session counters are preserved",
      );

      // Snapshot the visible counters so we can restore them after the reset
      final preservedCompleted = state.sessionCompletedCount;
      final preservedTotal = state.displayedSessionTotal;
      final preservedBytes = state.sessionUploadedBytes;
      final preservedStartTime = state.sessionStartTime;
      _logger.info("FULL RESTART step 1/6: signalling abort + cancelling all FileDownloader tasks");

      // 1. Tear down the FileDownloader queue at the iOS level (cancels all tasks +
      //    wipes localstore records). Wrapped with a timeout because on iOS with
      //    thousands of records, reset/delete can hang or hit EMFILE.
      try {
        await _uploadService.forceResetQueue().timeout(
          const Duration(seconds: 8),
          onTimeout: () {
            _logger.warning("FULL RESTART: forceResetQueue timed out after 8s, proceeding anyway");
          },
        );
      } catch (e, st) {
        _logger.severe("FULL RESTART: forceResetQueue threw, proceeding anyway", e, st);
      }
      _logger.info("FULL RESTART step 2/6: reset done");

      // 2. Clear visible upload items & ongoing flags, KEEP session totals
      state = state.copyWith(
        uploadItems: {},
        isStartingBackup: false,
        isCanceling: false,
        sessionCompletedCount: preservedCompleted,
        sessionTotalCount: preservedTotal,
        sessionUploadedBytes: preservedBytes,
        sessionStartTime: preservedStartTime,
        enqueueCount: 0,
        enqueueTotalCount: 0,
      );
      _logger.info("FULL RESTART step 3/6: state cleared, counters preserved ($preservedCompleted files)");

      // 3. Give iOS ~2s to actually release NSURLSession sockets
      await Future.delayed(const Duration(seconds: 2));
      _logger.info("FULL RESTART step 4/6: 2s wait done");

      // 4. Explicitly kick FileDownloader to make sure it processes fresh enqueues
      try {
        await _uploadService.resumeBackup();
      } catch (e, st) {
        _logger.warning("FULL RESTART: resumeBackup failed: $e", e, st);
      }
      _logger.info("FULL RESTART step 5/6: FileDownloader.start() called");

      // 5. Re-enqueue from scratch — same path as fresh app launch (handleBackupResume).
      //    continueBackup preserves session counters since sessionStartTime is set.
      if (_currentUserId != null) {
        _logger.info(
          "FULL RESTART step 6/6: re-enqueueing (session preserved: $preservedCompleted files / "
          "${(preservedBytes / (1024 * 1024)).toStringAsFixed(1)} MB)",
        );
        unawaited(continueBackup(_currentUserId!));
      } else {
        _logger.warning("FULL RESTART step 6/6: _currentUserId is null, cannot re-enqueue!");
      }

      // Reset stalled counter so we don't loop the restart every 60s during re-enqueue
      _stalledTicks = 0;
    } catch (e, st) {
      // EMFILE (errno 24, "Too many open files") happens on iOS when there
      // are too many task records in the FileDownloader localstore. The fix
      // (deleting records on completion) takes effect over time. Just warn here.
      final errStr = e.toString();
      if (errStr.contains('errno = 24') || errStr.contains('Too many open files')) {
        _logger.warning(
          "Backup health-check: hit iOS file descriptor limit (EMFILE) — will retry next tick. "
          "Completed task records are being cleaned up automatically.",
        );
      } else {
        _logger.severe("Backup health-check: recovery action failed", e, st);
      }
    }
  }

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
          final statusCode = update.responseStatusCode;
          // Accept any 2xx as success. The server may return:
          //  - 201 Created when a new asset is stored
          //  - 200 OK when the asset already exists server-side (duplicate by checksum)
          // Both mean "this file is safely backed up".
          final isSuccess = statusCode != null && statusCode >= 200 && statusCode < 300;
          if (isSuccess) {
            final completedItem = state.uploadItems[taskId];
            final uploadedBytes = completedItem?.fileSize ?? 0;
            final newCompleted = state.sessionCompletedCount + 1;
            final newTotalBytes = state.sessionUploadedBytes + uploadedBytes;

            // Log par-task COMPLETE : durée et débit effectif. Utile pour voir
            // quels fichiers prennent anormalement longtemps (gros vidéos,
            // PhotoKit lent, etc.).
            if (completedItem?.firstSeenAt != null) {
              final elapsed = DateTime.now().difference(completedItem!.firstSeenAt!);
              final mb = uploadedBytes / (1024 * 1024);
              final mbps = elapsed.inMilliseconds > 0
                  ? (mb / (elapsed.inMilliseconds / 1000.0))
                  : 0.0;
              _logger.info(
                "Task DONE (HTTP $statusCode): ${update.task.displayName} "
                "— ${mb.toStringAsFixed(1)}MB in ${elapsed.inSeconds}s "
                "(${mbps.toStringAsFixed(2)} MB/s)",
              );
            }

            // On NE marque PAS le fichier "sauvegardé" ici de façon optimiste.
            // backupCount / remainderCount restent pilotés par la vérité DB
            // (remote_asset_entity, rafraîchie en direct par les websockets
            // AssetUploadReadyV1 + le poller getBackupStatus). sessionCompletedCount
            // reste un compteur temps-réel des tâches terminées, utilisé
            // uniquement par le health-check pour détecter la progression.
            state = state.copyWith(
              sessionCompletedCount: newCompleted,
              sessionUploadedBytes: newTotalBytes,
            );
            _pushByteSample(newTotalBytes);
            _maybeTopUpQueue();
            if (newCompleted == 1 || newCompleted % 50 == 0) {
              _logger.info(
                "Upload progress: $newCompleted/${state.displayedSessionTotal} done (${update.task.displayName})",
              );
            }
          } else {
            _logger.warning(
              "Task BAD STATUS: ${update.task.displayName} — HTTP $statusCode (treated as failure)",
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

      case TaskStatus.waitingToRetry:
        // iOS a échoué une fois et programme un retry avec back-off. On le
        // laisse essayer (souvent ça réussit au 2e ou 3e essai). Si le retry
        // bloque vraiment longtemps, le sweeper 15s prendra le relais.
        _logger.info("Upload WAITING_TO_RETRY: ${update.task.displayName} — iOS scheduled a retry (back-off)");
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

    _ensureWatchdogRunning();

    final now = DateTime.now();

    if (currentItem != null) {
      if (progress == kUploadStatusCanceled) {
        _removeUploadItem(update.task.taskId);
        return;
      }

      // Détecte un "vrai" progress (bytes en mouvement) vs keepalive (même %).
      // Sert au health-check pour identifier les tasks bloqués individuellement.
      final hasRealProgress = progress > currentItem.progress + 0.001 || update.networkSpeed > 0;
      final newLastProgressAt = hasRealProgress ? now : currentItem.lastProgressAt;

      state = state.copyWith(
        uploadItems: {
          ...state.uploadItems,
          taskId: update.hasExpectedFileSize
              ? currentItem.copyWith(
                  progress: progress,
                  fileSize: update.expectedFileSize,
                  networkSpeedAsString: update.networkSpeedAsString,
                  networkSpeed: update.networkSpeed,
                  lastProgressAt: newLastProgressAt,
                )
              : currentItem.copyWith(
                  progress: progress,
                  networkSpeed: update.networkSpeed,
                  lastProgressAt: newLastProgressAt,
                ),
        },
      );

      return;
    }

    // Premier progress event pour ce task — log "task started"
    _logger.info(
      "Task STARTED: $filename "
      "(size=${(update.expectedFileSize / (1024 * 1024)).toStringAsFixed(1)}MB, taskId=$taskId)",
    );

    state = state.copyWith(
      uploadItems: {
        ...state.uploadItems,
        taskId: DriftUploadStatus(
          taskId: taskId,
          filename: filename,
          progress: progress,
          fileSize: update.expectedFileSize,
          networkSpeedAsString: update.networkSpeedAsString,
          firstSeenAt: now,
          lastProgressAt: now,
        ),
      },
    );
  }

  Future<void> getBackupStatus(String userId) async {
    final counts = await _uploadService.getBackupCounts(userId);

    // Vérité DB uniquement. Un fichier n'est "sauvegardé" que si son checksum
    // local correspond à une ligne remote_asset_entity — table remplie en direct
    // par les websockets AssetUploadReadyV1 pendant la session, et réconciliée
    // par syncRemote. Aucun optimisme en mémoire : backupCount monte au rythme
    // des confirmations serveur et ne recule jamais au redémarrage.
    // La progression de session (X / Y) est dérivée de ces valeurs via
    // sessionBaselineBackupCount (voir getters sessionCompleted / displayedSessionTotal).
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
    if (state.isStartingBackup) {
      _logger.info("startBackup: already running, skipping concurrent call");
      return;
    }
    // Note : on n'attend PAS la fin du hashing. Les fichiers déjà hashés
    // sont uploadés immédiatement, et au fur et à mesure que de nouveaux
    // fichiers deviennent disponibles, ils sont enqueués. Le total affiché
    // (displayedSessionTotal) se stabilise naturellement à la fin du hashing.
    _logger.info("startBackup: queuing candidates (remainder=${state.remainderCount})");
    _currentUserId = userId;
    _ensureWatchdogRunning();

    // If there's already a session in progress (handleBackupResume calling us
    // after the queue temporarily drained between batches), DO NOT reset the
    // visible counters — the user would see "0 / X" instead of their progress.
    // Treat this as a "continue", not a fresh start.
    final isFreshSession = state.sessionCompletedCount == 0 && state.sessionStartTime == null;

    // Pour une nouvelle session, on rafraîchit d'abord la vérité DB afin que la
    // base (sessionBaselineBackupCount) parte de la valeur réellement confirmée
    // par le serveur — certains chemins (toggle) appellent startBackup après un
    // syncRemote sans repasser par getBackupStatus, d'où backupCount potentiellement obsolète.
    if (isFreshSession) {
      await getBackupStatus(userId);
    }

    // Don't blindly set sessionTotalCount = remainderCount: if hashing hasn't
    // produced candidates yet (remainder=0), we'd lock the total at 0 forever.
    // Use the larger of (remainder, current total) so we never decrease it.
    final newTotal = state.remainderCount > state.sessionTotalCount
        ? state.remainderCount
        : state.sessionTotalCount;

    if (isFreshSession) {
      _byteSamples.clear(); // fresh session → fresh speed window
      state = state.copyWith(
        error: BackupError.none,
        sessionCompletedCount: 0,
        sessionTotalCount: newTotal,
        // Fige la base DB : X = backupCount - base. state.backupCount vient
        // d'être rafraîchi par le getBackupStatus ci-dessus (vérité DB).
        sessionBaselineBackupCount: state.backupCount,
        sessionStartTime: DateTime.now(),
        sessionUploadedBytes: 0,
        isStartingBackup: true,
        prepCandidateTotal: 0,
        prepCandidateProcessed: 0,
      );
    } else {
      _logger.info(
        "startBackup: continuing existing session (${state.sessionCompletedCount} files already uploaded) — counters preserved",
      );
      state = state.copyWith(
        error: BackupError.none,
        sessionTotalCount: newTotal,
        isStartingBackup: true,
        prepCandidateTotal: 0,
        prepCandidateProcessed: 0,
      );
    }
    try {
      await _uploadService.startBackup(userId, _updateEnqueueCount, _updatePrepProgress, _updateUnreachable);
      _logger.info(
        "startBackup: enqueued=${state.enqueueCount}/${state.enqueueTotalCount} prepared=${state.prepCandidateProcessed}/${state.prepCandidateTotal}",
      );
    } finally {
      state = state.copyWith(isStartingBackup: false);
    }
  }

  /// Top up the FileDownloader queue with newly-hashed candidates without
  /// resetting session counters. Used between batches once hashing is done.
  Future<void> continueBackup(String userId) async {
    if (state.isStartingBackup) return; // already enqueuing
    // Note : on enqueue même pendant le hashing — les fichiers déjà hashés
    // sont uploadés au fil de l'eau, ça maximise le débit.
    _logger.info("continueBackup: topping up queue (remainder=${state.remainderCount})");
    _currentUserId = userId;
    _ensureWatchdogRunning();
    // Lazily initialize the session if it wasn't started via startBackup.
    // Without this, sessionStartTime stays null → average speed is 0 → "— MB/s"
    // shown forever even while bytes are flowing.
    final initSession = state.sessionStartTime == null;
    if (initSession) {
      // Fige la baseline DB comme dans startBackup, sinon X/Y de la card
      // "Upload en cours" repartent du total global (ex: 11644/11660) au lieu
      // de la progression sur le restant de cette session (ex: 0/16).
      await getBackupStatus(userId);
    }
    state = state.copyWith(
      isStartingBackup: true,
      sessionStartTime: initSession ? DateTime.now() : null,
      sessionTotalCount: initSession ? state.remainderCount : null,
      sessionBaselineBackupCount: initSession ? state.backupCount : null,
    );
    try {
      await _uploadService.startBackup(userId, _updateEnqueueCount, _updatePrepProgress, _updateUnreachable);
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

  void _updateUnreachable(int unreachable) {
    if (state.unreachableCount != unreachable) {
      state = state.copyWith(unreachableCount: unreachable);
    }
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

  bool _isResumingBackup = false;

  Future<void> handleBackupResume(String userId) async {
    // Guard against concurrent resume calls (iOS app lifecycle can fire resume
    // multiple times in quick succession when foregrounding the app)
    if (_isResumingBackup) {
      _logger.info("handleBackupResume: already running, skipping");
      return;
    }
    _isResumingBackup = true;
    try {
      _currentUserId = userId;
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
    } finally {
      _isResumingBackup = false;
    }
  }

  @override
  void dispose() {
    _statusSubscription?.cancel();
    _progressSubscription?.cancel();
    _stalledWatchdog?.cancel();
    _retrySweeper?.cancel();
    _queueKicker?.cancel();
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
