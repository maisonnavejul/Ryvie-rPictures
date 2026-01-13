import 'dart:async';
import 'dart:io';

import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/domain/utils/background_sync.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/models/auth/auxilary_endpoint.model.dart';
import 'package:immich_mobile/models/auth/login_response.model.dart';
import 'package:immich_mobile/providers/api.provider.dart';
import 'package:immich_mobile/providers/app_settings.provider.dart';
import 'package:immich_mobile/providers/background_sync.provider.dart';
import 'package:immich_mobile/repositories/auth.repository.dart';
import 'package:immich_mobile/repositories/auth_api.repository.dart';
import 'package:immich_mobile/services/api.service.dart';
import 'package:immich_mobile/services/app_settings.service.dart';
import 'package:immich_mobile/services/network.service.dart';
import 'package:immich_mobile/services/smart_url_selector.service.dart';
import 'package:logging/logging.dart';
import 'package:openapi/api.dart';

final authServiceProvider = Provider(
  (ref) => AuthService(
    ref.watch(authApiRepositoryProvider),
    ref.watch(authRepositoryProvider),
    ref.watch(apiServiceProvider),
    ref.watch(networkServiceProvider),
    ref.watch(backgroundSyncProvider),
    ref.watch(appSettingsServiceProvider),
  ),
);

class AuthService {
  final AuthApiRepository _authApiRepository;
  final AuthRepository _authRepository;
  final ApiService _apiService;
  final NetworkService _networkService;
  final BackgroundSyncManager _backgroundSyncManager;
  final AppSettingsService _appSettingsService;
  final SmartUrlSelectorService _smartUrlSelector = SmartUrlSelectorService();
  final _log = Logger("AuthService");

  AuthService(
    this._authApiRepository,
    this._authRepository,
    this._apiService,
    this._networkService,
    this._backgroundSyncManager,
    this._appSettingsService,
  );

  /// Validates the provided server URL by resolving and setting the endpoint.
  /// Also sets the device info header and stores the valid URL.
  ///
  /// [url] - The server URL to be validated.
  ///
  /// Returns the validated and resolved server URL as a [String].
  ///
  /// Throws an exception if the URL cannot be resolved or set.
  Future<String> validateServerUrl(String url) async {
    final validUrl = await _apiService.resolveAndSetEndpoint(url);
    await _apiService.setDeviceInfoHeader();
    await Store.put(StoreKey.serverUrl, validUrl);

    return validUrl;
  }

  /// Sauvegarde les informations du tunnel pour la sélection intelligente d'URL
  ///
  /// [ryvieId] - L'identifiant unique du Ryvie
  /// [tunnelHost] - L'adresse IP ou hostname du tunnel
  /// [publicUrl] - L'URL publique complète (optionnel)
  Future<void> saveTunnelInfo({String? ryvieId, String? tunnelHost, String? publicUrl}) async {
    await _smartUrlSelector.saveTunnelInfo(ryvieId: ryvieId, tunnelHost: tunnelHost, publicUrl: publicUrl);
  }

  /// Récupère les informations du tunnel sauvegardées
  ({String? ryvieId, String? tunnelHost, String? publicUrl}) getTunnelInfo() {
    return _smartUrlSelector.getSavedTunnelInfo();
  }

  /// Tente de switcher automatiquement vers l'URL appropriée (locale ou tunnel)
  /// Retourne l'URL sélectionnée ou null en cas d'échec
  Future<String?> trySmartUrlSwitch() async {
    try {
      _log.info('🔄 Tentative de switch intelligent d\'URL...');
      final result = await _smartUrlSelector.selectServerUrl();

      _log.info('✅ URL sélectionnée: ${result.url} (local: ${result.isLocal})');

      // Mettre à jour l'endpoint de l'API
      await _apiService.resolveAndSetEndpoint(result.url);
      await Store.put(StoreKey.serverUrl, result.url);

      return result.url;
    } catch (error, stackTrace) {
      _log.severe('❌ Échec du switch intelligent d\'URL', error, stackTrace);
      return null;
    }
  }

  Future<bool> validateAuxilaryServerUrl(String url) async {
    final httpclient = HttpClient();
    bool isValid = false;

    try {
      final uri = Uri.parse('$url/users/me');
      final request = await httpclient.getUrl(uri);

      // add auth token + any configured custom headers
      final customHeaders = ApiService.getRequestHeaders();
      customHeaders.forEach((key, value) {
        request.headers.add(key, value);
      });

      final response = await request.close();
      if (response.statusCode == 200) {
        isValid = true;
      }
    } catch (error) {
      _log.severe("Error validating auxiliary endpoint", error);
    } finally {
      httpclient.close();
    }

    return isValid;
  }

  Future<LoginResponse> login(String email, String password) {
    return _authApiRepository.login(email, password);
  }

  /// Performs user logout operation by making a server request and clearing local data.
  ///
  /// This method attempts to log out the user through the authentication API repository.
  /// If the server request fails, the error is logged but local data is still cleared.
  /// The local data cleanup is guaranteed to execute regardless of the server request outcome.
  ///
  /// Throws any unhandled exceptions from the API request or local data clearing operations.
  Future<void> logout() async {
    try {
      await _authApiRepository.logout();
    } catch (error, stackTrace) {
      _log.severe("Error logging out", error, stackTrace);
    } finally {
      await clearLocalData().catchError((error, stackTrace) {
        _log.severe("Error clearing local data", error, stackTrace);
      });

      await _appSettingsService.setSetting(AppSettingsEnum.enableBackup, false);
    }
  }

  /// Clears all local authentication-related data.
  ///
  /// This method performs a concurrent deletion of:
  /// - Authentication repository data
  /// - Current user information
  /// - Access token
  /// - Asset ETag
  /// - Tunnel information
  ///
  /// All deletions are executed in parallel using [Future.wait].
  Future<void> clearLocalData() async {
    // Cancel any ongoing background sync operations before clearing data
    await _backgroundSyncManager.cancel();
    await Future.wait([
      _authRepository.clearLocalData(),
      Store.delete(StoreKey.currentUser),
      Store.delete(StoreKey.accessToken),
      Store.delete(StoreKey.assetETag),
      Store.delete(StoreKey.autoEndpointSwitching),
      Store.delete(StoreKey.preferredWifiName),
      Store.delete(StoreKey.localEndpoint),
      Store.delete(StoreKey.externalEndpointList),
      Store.delete(StoreKey.ryvieId),
      Store.delete(StoreKey.tunnelHost),
      Store.delete(StoreKey.publicUrl),
    ]);
  }

  Future<void> changePassword(String newPassword) {
    try {
      return _authApiRepository.changePassword(newPassword);
    } catch (error, stackTrace) {
      _log.severe("Error changing password", error, stackTrace);
      rethrow;
    }
  }

  Future<String?> setOpenApiServiceEndpoint({bool forceTunnel = false}) async {
    // Toujours essayer la sélection intelligente d'URL en premier (ryvie.local:3013 en priorité)
    try {
      final result = forceTunnel
          ? await _smartUrlSelector.selectTunnelUrl()
          : await _smartUrlSelector.selectServerUrl();

      if (result == null) {
        throw Exception('NO_TUNNEL_CONFIG');
      }
      _log.info('✅ Sélection intelligente URL: ${result.url} (local: ${result.isLocal})');

      if (result.url.isNotEmpty) {
        // On a déjà une URL de base fiable (locale ou tunnel).
        // On définit directement l'endpoint API sans repasser par la découverte
        // /.well-known/immich, qui peut être bloquée côté tunnel.

        // Construire l'endpoint API (base + /api si nécessaire)
        var apiBase = result.url;
        if (!apiBase.endsWith('/api')) {
          apiBase = '$apiBase/api';
        }

        // Mettre à jour l'ApiService et le store
        _apiService.setEndpoint(apiBase);
        await Store.put(StoreKey.serverEndpoint, apiBase);
        await Store.put(StoreKey.serverUrl, result.url);

        _log.info('✅ Endpoint configuré: $apiBase (local: ${result.isLocal})');
        return result.url;
      }
    } catch (error, stackTrace) {
      final errorStr = error.toString();

      if (errorStr.contains('NO_TUNNEL_CONFIG')) {
        _log.severe('❌ Pas de configuration tunnel');
        // L'erreur sera gérée par le provider qui appelle cette méthode
        rethrow;
      }

      _log.warning(
        '⚠️  Erreur lors de la sélection intelligente URL, fallback sur méthode classique',
        error,
        stackTrace,
      );
    }

    // Fallback sur l'ancienne méthode si la sélection intelligente échoue
    final enable = _authRepository.getEndpointSwitchingFeature();
    if (!enable) {
      _log.info('ℹ️  Endpoint switching désactivé, pas de fallback');
      return null;
    }

    final wifiName = await _networkService.getWifiName();
    final savedWifiName = _authRepository.getPreferredWifiName();
    String? endpoint;

    if (wifiName == savedWifiName) {
      endpoint = await _setLocalConnection();
    }

    endpoint ??= await _setRemoteConnection();

    return endpoint;
  }

  Future<String?> _setLocalConnection() async {
    try {
      final localEndpoint = _authRepository.getLocalEndpoint();
      if (localEndpoint != null) {
        await _apiService.resolveAndSetEndpoint(localEndpoint);
        return localEndpoint;
      }
    } catch (error, stackTrace) {
      _log.severe("Cannot set local endpoint", error, stackTrace);
    }

    return null;
  }

  Future<String?> _setRemoteConnection() async {
    List<AuxilaryEndpoint> endpointList;

    try {
      endpointList = _authRepository.getExternalEndpointList();
    } catch (error, stackTrace) {
      _log.severe("Cannot get external endpoint", error, stackTrace);
      return null;
    }

    for (final endpoint in endpointList) {
      try {
        return await _apiService.resolveAndSetEndpoint(endpoint.url);
      } on ApiException catch (error) {
        _log.severe("Cannot resolve endpoint", error);
        continue;
      } catch (_) {
        _log.severe("Auxiliary server is not valid");
        continue;
      }
    }

    return null;
  }

  Future<bool> unlockPinCode(String pinCode) {
    return _authApiRepository.unlockPinCode(pinCode);
  }

  Future<void> lockPinCode() {
    return _authApiRepository.lockPinCode();
  }

  Future<void> setupPinCode(String pinCode) {
    return _authApiRepository.setupPinCode(pinCode);
  }
}
