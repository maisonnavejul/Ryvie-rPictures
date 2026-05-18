import 'package:flutter/services.dart';
import 'package:immich_mobile/constants/constants.dart';
import 'package:immich_mobile/domain/models/album/local_album.model.dart';
import 'package:immich_mobile/domain/models/asset/base_asset.model.dart';
import 'package:immich_mobile/infrastructure/repositories/local_album.repository.dart';
import 'package:immich_mobile/infrastructure/repositories/local_asset.repository.dart';
import 'package:immich_mobile/platform/native_sync_api.g.dart';
import 'package:logging/logging.dart';

const String _kHashCancelledCode = "HASH_CANCELLED";

class HashService {
  final int _batchSize;
  final DriftLocalAlbumRepository _localAlbumRepository;
  final DriftLocalAssetRepository _localAssetRepository;
  final NativeSyncApi _nativeSyncApi;
  final bool Function()? _cancelChecker;
  final _log = Logger('HashService');

  /// Asset IDs that have failed hashing during this app session — typically
  /// iCloud-optimised originals that PhotoKit refuses to return locally.
  /// Skipping them prevents the hash loop from spamming the logs and burning
  /// CPU re-attempting the same files on every sync.
  static final Set<String> _failedAssetIds = <String>{};

  HashService({
    required DriftLocalAlbumRepository localAlbumRepository,
    required DriftLocalAssetRepository localAssetRepository,
    required NativeSyncApi nativeSyncApi,
    bool Function()? cancelChecker,
    int? batchSize,
  }) : _localAlbumRepository = localAlbumRepository,
       _localAssetRepository = localAssetRepository,
       _cancelChecker = cancelChecker,
       _nativeSyncApi = nativeSyncApi,
       _batchSize = batchSize ?? kBatchHashFileLimit;

  bool get isCancelled => _cancelChecker?.call() ?? false;

  Future<void> hashAssets() async {
    _log.info("Starting hashing of assets");
    final Stopwatch stopwatch = Stopwatch()..start();
    try {
      // Sorted by backupSelection followed by isCloud
      final localAlbums = await _localAlbumRepository.getBackupAlbums();

      for (final album in localAlbums) {
        if (isCancelled) {
          _log.warning("Hashing cancelled. Stopped processing albums.");
          break;
        }

        final assetsToHash = await _localAlbumRepository.getAssetsToHash(album.id);
        if (assetsToHash.isNotEmpty) {
          await _hashAssets(album, assetsToHash);
        }
      }
    } on PlatformException catch (e) {
      if (e.code == _kHashCancelledCode) {
        _log.warning("Hashing cancelled by platform");
        return;
      }
    } catch (e, s) {
      _log.severe("Error during hashing", e, s);
    }

    stopwatch.stop();
    _log.info("Hashing took - ${stopwatch.elapsedMilliseconds}ms");
  }

  /// Processes a list of [LocalAsset]s, storing their hash and updating the assets in the DB
  /// with hash for those that were successfully hashed. Hashes are looked up in a table
  /// [LocalAssetHashEntity] by local id. Only missing entries are newly hashed and added to the DB.
  Future<void> _hashAssets(LocalAlbum album, List<LocalAsset> assetsToHash) async {
    final toHash = <String, LocalAsset>{};
    int skipped = 0;

    for (final asset in assetsToHash) {
      if (isCancelled) {
        _log.warning("Hashing cancelled. Stopped processing assets.");
        return;
      }

      // Skip assets that already failed in this session (e.g. iCloud-only originals).
      // They'll be retried on next app launch.
      if (_failedAssetIds.contains(asset.id)) {
        skipped++;
        continue;
      }

      toHash[asset.id] = asset;
      if (toHash.length == _batchSize) {
        await _processBatch(album, toHash);
        toHash.clear();
      }
    }

    await _processBatch(album, toHash);

    if (skipped > 0) {
      _log.fine("Skipped $skipped previously-failed assets in album '${album.name}'");
    }
  }

  /// Processes a batch of assets.
  Future<void> _processBatch(LocalAlbum album, Map<String, LocalAsset> toHash) async {
    if (toHash.isEmpty) {
      return;
    }

    _log.fine("Hashing ${toHash.length} files");

    final hashed = <String, String>{};
    final hashResults = await _nativeSyncApi.hashAssets(
      toHash.keys.toList(),
      allowNetworkAccess: album.backupSelection == BackupSelection.selected,
    );
    assert(
      hashResults.length == toHash.length,
      "Hashes length does not match toHash length: ${hashResults.length} != ${toHash.length}",
    );

    for (int i = 0; i < hashResults.length; i++) {
      if (isCancelled) {
        _log.warning("Hashing cancelled. Stopped processing batch.");
        return;
      }

      final hashResult = hashResults[i];
      if (hashResult.hash != null) {
        hashed[hashResult.assetId] = hashResult.hash!;
        // In case the asset was previously failed (e.g. iCloud downloaded later) — clear the skip flag
        _failedAssetIds.remove(hashResult.assetId);
      } else {
        // Remember the failure so we don't retry it in the same session
        _failedAssetIds.add(hashResult.assetId);
        final asset = toHash[hashResult.assetId];
        final errorMsg = hashResult.error ?? "unknown";
        // PHPhotosErrorDomain -1 means "asset not available locally" (iCloud-optimised storage).
        // This is expected and not actionable — log at fine level to avoid spamming logs.
        final isExpectedICloudError = errorMsg.contains("PHPhotosErrorDomain");
        if (isExpectedICloudError) {
          _log.fine(
            "Asset not locally available (iCloud): ${asset?.name} [${hashResult.assetId}]",
          );
        } else {
          _log.warning(
            "Failed to hash asset with id: ${hashResult.assetId}, name: ${asset?.name}, createdAt: ${asset?.createdAt}, from album: ${album.name}. Error: $errorMsg",
          );
        }
      }
    }

    _log.fine("Hashed ${hashed.length}/${toHash.length} assets");

    await _localAssetRepository.updateHashes(hashed);
  }
}
