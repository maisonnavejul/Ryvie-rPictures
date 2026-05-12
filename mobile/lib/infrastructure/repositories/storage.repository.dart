import 'dart:io';

import 'package:immich_mobile/domain/models/asset/base_asset.model.dart';
import 'package:immich_mobile/extensions/platform_extensions.dart';
import 'package:logging/logging.dart';
import 'package:photo_manager/photo_manager.dart';

class StorageRepository {
  const StorageRepository();

  // Skip assets that take more than this to resolve — typically iCloud-only photos
  // that would block the prep loop while iOS downloads them.
  static const _resolveTimeout = Duration(seconds: 3);

  Future<File?> getFileForAsset(String assetId) async {
    File? file;
    final log = Logger('StorageRepository');

    try {
      final entity = await AssetEntity.fromId(assetId);
      if (entity == null) return null;
      file = await entity.originFile.timeout(_resolveTimeout, onTimeout: () => null);
      if (file == null) {
        log.fine("Skipping asset $assetId (not locally available or timed out)");
        return null;
      }

      final exists = await file.exists();
      if (!exists) {
        log.fine("File for asset $assetId does not exist locally");
        return null;
      }
    } catch (error, stackTrace) {
      // PHPhotosErrorDomain (-1) = asset not locally available (iCloud) - common, don't spam logs
      final isExpected = error.toString().contains('PHPhotosErrorDomain');
      if (isExpected) {
        log.fine("Asset $assetId not locally available (iCloud)");
      } else {
        log.warning("Error getting file for asset $assetId", error, stackTrace);
      }
    }
    return file;
  }

  Future<File?> getMotionFileForAsset(LocalAsset asset) async {
    File? file;
    final log = Logger('StorageRepository');

    try {
      final entity = await AssetEntity.fromId(asset.id);
      if (entity == null) return null;
      file = await entity.originFileWithSubtype.timeout(_resolveTimeout, onTimeout: () => null);
      if (file == null) {
        log.fine(
          "Skipping motion file for asset ${asset.id} (not locally available or timed out)",
        );
        return null;
      }

      final exists = await file.exists();
      if (!exists) {
        log.fine("Motion file for asset ${asset.id} does not exist locally");
        return null;
      }
    } catch (error, stackTrace) {
      // PHPhotosErrorDomain 3169 = motion file not available - common, don't spam logs
      final isExpected = error.toString().contains('3169') || error.toString().contains('PHPhotosErrorDomain');
      if (isExpected) {
        log.fine("Motion file unavailable for ${asset.id}");
      } else {
        log.warning(
          "Error getting motion file for asset ${asset.id}, name: ${asset.name}, created on: ${asset.createdAt}",
          error,
          stackTrace,
        );
      }
    }
    return file;
  }

  Future<AssetEntity?> getAssetEntityForAsset(LocalAsset asset) async {
    final log = Logger('StorageRepository');

    AssetEntity? entity;

    try {
      entity = await AssetEntity.fromId(asset.id);
      if (entity == null) {
        log.warning(
          "Cannot get AssetEntity for asset ${asset.id}, name: ${asset.name}, created on: ${asset.createdAt}",
        );
      }
    } catch (error, stackTrace) {
      log.warning(
        "Error getting AssetEntity for asset ${asset.id}, name: ${asset.name}, created on: ${asset.createdAt}",
        error,
        stackTrace,
      );
    }
    return entity;
  }

  Future<void> clearCache() async {
    final log = Logger('StorageRepository');

    try {
      await PhotoManager.clearFileCache();
    } catch (error, stackTrace) {
      log.warning("Error clearing cache", error, stackTrace);
    }

    if (!CurrentPlatform.isIOS) {
      return;
    }

    try {
      if (await Directory.systemTemp.exists()) {
        await Directory.systemTemp.delete(recursive: true);
      }
    } catch (error, stackTrace) {
      log.warning("Error deleting temporary directory", error, stackTrace);
    }
  }
}
