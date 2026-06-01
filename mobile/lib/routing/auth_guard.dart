import 'dart:async';
import 'dart:io';

import 'package:auto_route/auto_route.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/domain/services/store.service.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/routing/router.dart';
import 'package:immich_mobile/services/api.service.dart';
import 'package:logging/logging.dart';
import 'package:openapi/api.dart';

class AuthGuard extends AutoRouteGuard {
  final ApiService _apiService;
  final _log = Logger("AuthGuard");
  AuthGuard(this._apiService);
  @override
  void onNavigation(NavigationResolver resolver, StackRouter router) async {
    resolver.next(true);

    try {
      // Look in the store for an access token
      Store.get(StoreKey.accessToken);

      // Validate the access token with the server
      final res = await _apiService.authenticationApi.validateAccessToken();
      if (res == null || res.authStatus != true) {
        // Token rejeté par le serveur — peut être un mauvais Ryvie (réseau
        // étranger) plutôt qu'un vrai token invalide. On NE redirige PAS
        // automatiquement : l'utilisateur ne doit pas être déconnecté juste
        // parce qu'on a interrogé le mauvais serveur.
        _log.warning('Token rejected by server — staying on current route (no auto-disconnect)');
      }
    } on StoreKeyNotFoundException catch (_) {
      // Pas du tout de token = première installation ou données effacées.
      // Là c'est légitime de router vers Login (rien à utiliser).
      _log.info('No access token in the store — routing to Login');
      unawaited(router.replaceAll([const LoginRoute()]));
      return;
    } on ApiException catch (e) {
      // 401 sur la validation = même raisonnement que ci-dessus : peut-être
      // qu'on tape sur le mauvais Ryvie. Pas de redirection automatique.
      if (e.code == HttpStatus.unauthorized) {
        _log.warning("Token unauthorized by server — staying on current route (no auto-disconnect)");
      }
    } catch (e) {
      // Otherwise, this is not fatal, but we still log the warning
      _log.warning('Error validating access token from server: $e');
    }
  }
}
