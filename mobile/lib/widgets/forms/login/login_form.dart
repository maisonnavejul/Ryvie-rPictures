import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:auto_route/auto_route.dart';
import 'package:crypto/crypto.dart';
import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hooks/flutter_hooks.dart' hide Store;
import 'package:fluttertoast/fluttertoast.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/extensions/build_context_extensions.dart';
import 'package:immich_mobile/extensions/theme_extensions.dart';
import 'package:immich_mobile/providers/auth.provider.dart';
import 'package:immich_mobile/providers/background_sync.provider.dart';
import 'package:immich_mobile/providers/backup/backup.provider.dart';
import 'package:immich_mobile/providers/gallery_permission.provider.dart';
import 'package:immich_mobile/providers/oauth.provider.dart';
import 'package:immich_mobile/providers/server_info.provider.dart';
import 'package:immich_mobile/providers/websocket.provider.dart';
import 'package:immich_mobile/routing/router.dart';
import 'package:immich_mobile/utils/provider_utils.dart';
import 'package:immich_mobile/utils/url_helper.dart';
import 'package:immich_mobile/utils/version_compatibility.dart';
import 'package:immich_mobile/widgets/common/immich_logo.dart';
import 'package:immich_mobile/widgets/common/immich_title_text.dart';
import 'package:immich_mobile/widgets/common/immich_toast.dart';
import 'package:immich_mobile/widgets/forms/login/email_input.dart';
import 'package:immich_mobile/widgets/forms/login/loading_icon.dart';
import 'package:immich_mobile/widgets/forms/login/login_button.dart';
import 'package:immich_mobile/widgets/forms/login/o_auth_login_button.dart';
import 'package:immich_mobile/widgets/forms/login/password_input.dart';
import 'package:immich_mobile/widgets/forms/login/server_endpoint_input.dart';
import 'package:immich_mobile/services/smart_url_selector.service.dart';
import 'package:immich_mobile/providers/connection_status.provider.dart';
import 'package:logging/logging.dart';
import 'package:openapi/api.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:permission_handler/permission_handler.dart';

class LoginForm extends HookConsumerWidget {
  LoginForm({super.key});

  final log = Logger('LoginForm');

  /// Affiche un dialogue d'avertissement avant de changer de Ryvie
  void _showChangeRyvieDialog(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        icon: const Icon(Icons.warning_amber_rounded, size: 48, color: Colors.orange),
        title: const Text(
          'Changer de Ryvie',
          textAlign: TextAlign.center,
          style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
        ),
        content: const SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Pour vous connecter à un nouveau Ryvie, vous devez être sur le même réseau WiFi que ce Ryvie.',
                style: TextStyle(fontSize: 15, height: 1.4),
              ),
              SizedBox(height: 16),
              Text(
                '⚠️ Votre ancienne connexion sera perdue.',
                style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold, color: Colors.orange),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Annuler')),
          FilledButton(
            onPressed: () async {
              Navigator.of(context).pop();

              // Effacer TOUTES les données (y compris ryvieId, tunnelHost, publicUrl)
              await ref.read(authProvider.notifier).clearAllData();

              // Afficher un message de confirmation
              if (context.mounted) {
                ImmichToast.show(
                  context: context,
                  msg: 'Toutes les données effacées. Connectez-vous au WiFi de votre nouveau Ryvie.',
                  toastType: ToastType.success,
                );
              }
            },
            child: const Text('Continuer'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final emailController = useTextEditingController.fromValue(TextEditingValue.empty);
    final passwordController = useTextEditingController.fromValue(TextEditingValue.empty);
    final serverEndpointController = useTextEditingController.fromValue(TextEditingValue.empty);
    final emailFocusNode = useFocusNode();
    final passwordFocusNode = useFocusNode();
    final serverEndpointFocusNode = useFocusNode();
    final isLoading = useState<bool>(false);
    final isLoadingServer = useState<bool>(false);
    final isOauthEnable = useState<bool>(false);
    final isPasswordLoginEnable = useState<bool>(false);
    final oAuthButtonLabel = useState<String>('OAuth');
    final logoAnimationController = useAnimationController(duration: const Duration(seconds: 60))..repeat();
    final serverInfo = ref.watch(serverInfoProvider);
    final warningMessage = useState<String?>(null);
    final loginFormKey = GlobalKey<FormState>();
    final ValueNotifier<String?> serverEndpoint = useState<String?>(null);

    checkVersionMismatch() async {
      try {
        final packageInfo = await PackageInfo.fromPlatform();
        final appVersion = packageInfo.version;
        final appMajorVersion = int.parse(appVersion.split('.')[0]);
        final appMinorVersion = int.parse(appVersion.split('.')[1]);
        final serverMajorVersion = serverInfo.serverVersion.major;
        final serverMinorVersion = serverInfo.serverVersion.minor;

        warningMessage.value = getVersionCompatibilityMessage(
          appMajorVersion,
          appMinorVersion,
          serverMajorVersion,
          serverMinorVersion,
        );
      } catch (error) {
        warningMessage.value = 'Error checking version compatibility';
      }
    }

    /// Fetch the server login credential and enables oAuth login if necessary
    /// Returns true if successful, false otherwise
    Future<void> getServerAuthSettings() async {
      final sanitizeServerUrl = sanitizeUrl(serverEndpointController.text);
      final serverUrl = punycodeEncodeUrl(sanitizeServerUrl);

      // Guard empty URL
      if (serverUrl.isEmpty) {
        ImmichToast.show(context: context, msg: "login_form_server_empty".tr(), toastType: ToastType.error);
      }

      try {
        isLoadingServer.value = true;
        final endpoint = await ref.read(authProvider.notifier).validateServerUrl(serverUrl);

        // Fetch and load server config and features
        await ref.read(serverInfoProvider.notifier).getServerInfo();

        final serverInfo = ref.read(serverInfoProvider);
        final features = serverInfo.serverFeatures;
        final config = serverInfo.serverConfig;

        isOauthEnable.value = features.oauthEnabled;
        isPasswordLoginEnable.value = features.passwordLogin;
        oAuthButtonLabel.value = config.oauthButtonText.isNotEmpty ? config.oauthButtonText : 'OAuth';

        serverEndpoint.value = endpoint;
      } on ApiException catch (e) {
        ImmichToast.show(
          context: context,
          msg: e.message ?? 'login_form_api_exception'.tr(),
          toastType: ToastType.error,
          gravity: ToastGravity.TOP,
        );
        isOauthEnable.value = false;
        isPasswordLoginEnable.value = true;
        isLoadingServer.value = false;
      } on HandshakeException {
        ImmichToast.show(
          context: context,
          msg: 'login_form_handshake_exception'.tr(),
          toastType: ToastType.error,
          gravity: ToastGravity.TOP,
        );
        isOauthEnable.value = false;
        isPasswordLoginEnable.value = true;
        isLoadingServer.value = false;
      } catch (e) {
        ImmichToast.show(
          context: context,
          msg: 'login_form_server_error'.tr(),
          toastType: ToastType.error,
          gravity: ToastGravity.TOP,
        );
        isOauthEnable.value = false;
        isPasswordLoginEnable.value = true;
        isLoadingServer.value = false;
      }

      isLoadingServer.value = false;
    }

    useEffect(() {
      // Essayer d'abord la connexion locale automatique (comme Ryvie-Desktop)
      tryAutoConnectLocal() async {
        log.info('🔍 Tentative de connexion automatique au serveur local...');

        try {
          // Tester si ryvie.local:3013 est accessible
          final smartUrlSelector = SmartUrlSelectorService();
          final result = await smartUrlSelector.selectServerUrl();

          if (result.isLocal && result.url == SmartUrlSelectorService.localServerUrl) {
            // Connexion locale disponible - se connecter automatiquement
            log.info('✅ Serveur local détecté - Connexion automatique à ${result.url}');
            serverEndpointController.text = result.url;

            // Récupérer automatiquement les infos du tunnel en arrière-plan
            smartUrlSelector.fetchAndSaveTunnelInfo().catchError((e) {
              log.warning('Erreur récupération infos tunnel: $e');
            });

            // Valider automatiquement le serveur
            await getServerAuthSettings();
          } else {
            // Connexion via tunnel - se connecter automatiquement
            log.info('✅ Connexion via tunnel détectée - Utilisation de ${result.url}');
            serverEndpointController.text = result.url;
            await getServerAuthSettings();
          }
        } catch (e) {
          // Erreur de connexion - mettre à jour le provider pour afficher le message
          final errorStr = e.toString();
          log.info('🔍 DEBUG Login: errorStr = $errorStr');

          if (errorStr.contains('TUNNEL_UNAVAILABLE')) {
            log.severe('❌ Tunnel inaccessible');
            ref
                .read(connectionStatusProvider.notifier)
                .setTunnelUnavailable(
                  'Impossible de se connecter à votre Ryvie.\n\n'
                  'Vérifiez que :\n'
                  '• Votre téléphone a accès à Internet\n'
                  '• L\'application Ryvie Connect est ouverte sur votre téléphone principal\n\n'
                  'Si vous êtes chez vous, reconnectez-vous au WiFi.',
                );
          } else if (errorStr.contains('NO_TUNNEL_CONFIG')) {
            log.severe('❌ Pas de configuration tunnel');
            ref
                .read(connectionStatusProvider.notifier)
                .setNoTunnelConfig(
                  'Pour accéder à votre Ryvie depuis l\'extérieur :\n\n'
                  '1. Connectez-vous au WiFi de votre domicile\n'
                  '2. Ouvrez rPictures\n'
                  '3. Installez l\'application Ryvie Connect sur votre téléphone principal',
                );
          } else {
            log.severe('❌ Erreur de connexion: $e');
          }

          // Utiliser l'URL sauvegardée si disponible
          final serverUrl = getServerUrl();
          if (serverUrl != null) {
            log.info('ℹ️  Utilisation de l\'URL sauvegardée: $serverUrl');
            serverEndpointController.text = serverUrl;
          }
        }
      }

      tryAutoConnectLocal();
      return null;
    }, []);

    populateTestLoginInfo() {
      emailController.text = 'demo@immich.app';
      passwordController.text = 'demo';
      serverEndpointController.text = 'https://demo.immich.app';
    }

    populateTestLoginInfo1() {
      emailController.text = 'testuser@email.com';
      passwordController.text = 'password';
      serverEndpointController.text = 'http://10.1.15.216:2283/api';
    }

    Future<void> handleSyncFlow() async {
      final backgroundManager = ref.read(backgroundSyncProvider);

      await backgroundManager.syncLocal(full: true);
      await backgroundManager.syncRemote();
      await backgroundManager.hashAssets();

      if (Store.get(StoreKey.syncAlbums, false)) {
        await backgroundManager.syncLinkedAlbum();
      }
    }

    login() async {
      TextInput.finishAutofillContext();

      isLoading.value = true;

      // Invalidate all api repository provider instance to take into account new access token
      invalidateAllApiRepositoryProviders(ref);

      try {
        final result = await ref.read(authProvider.notifier).login(emailController.text, passwordController.text);

        if (result.shouldChangePassword && !result.isAdmin) {
          unawaited(context.pushRoute(const ChangePasswordRoute()));
        } else {
          final isBeta = Store.isBetaTimelineEnabled;
          if (isBeta) {
            await ref.read(galleryPermissionNotifier.notifier).requestGalleryPermission();
            unawaited(handleSyncFlow());
            ref.read(websocketProvider.notifier).connect();
            unawaited(context.replaceRoute(const TabShellRoute()));
            return;
          }
          unawaited(context.replaceRoute(const TabControllerRoute()));
        }
      } catch (error) {
        ImmichToast.show(
          context: context,
          msg: "login_form_failed_login".tr(),
          toastType: ToastType.error,
          gravity: ToastGravity.TOP,
        );
      } finally {
        isLoading.value = false;
      }
    }

    String generateRandomString(int length) {
      const chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
      final random = Random.secure();
      return String.fromCharCodes(Iterable.generate(length, (_) => chars.codeUnitAt(random.nextInt(chars.length))));
    }

    List<int> randomBytes(int length) {
      final random = Random.secure();
      return List<int>.generate(length, (i) => random.nextInt(256));
    }

    /// Per specification, the code verifier must be 43-128 characters long
    /// and consist of characters [A-Z, a-z, 0-9, "-", ".", "_", "~"]
    /// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
    String randomCodeVerifier() {
      return base64Url.encode(randomBytes(42));
    }

    Future<String> generatePKCECodeChallenge(String codeVerifier) async {
      var bytes = utf8.encode(codeVerifier);
      var digest = sha256.convert(bytes);
      return base64Url.encode(digest.bytes).replaceAll('=', '');
    }

    oAuthLogin() async {
      var oAuthService = ref.watch(oAuthServiceProvider);
      String? oAuthServerUrl;

      final state = generateRandomString(32);

      final codeVerifier = randomCodeVerifier();
      final codeChallenge = await generatePKCECodeChallenge(codeVerifier);

      try {
        oAuthServerUrl = await oAuthService.getOAuthServerUrl(
          sanitizeUrl(serverEndpointController.text),
          state,
          codeChallenge,
        );

        isLoading.value = true;

        // Invalidate all api repository provider instance to take into account new access token
        invalidateAllApiRepositoryProviders(ref);
      } catch (error, stack) {
        log.severe('Error getting OAuth server Url: $error', stack);

        ImmichToast.show(
          context: context,
          msg: "login_form_failed_get_oauth_server_config".tr(),
          toastType: ToastType.error,
          gravity: ToastGravity.TOP,
        );
        isLoading.value = false;
        return;
      }

      if (oAuthServerUrl != null) {
        try {
          final loginResponseDto = await oAuthService.oAuthLogin(oAuthServerUrl, state, codeVerifier);

          if (loginResponseDto == null) {
            return;
          }

          log.info("Finished OAuth login with response: ${loginResponseDto.userEmail}");

          final isSuccess = await ref
              .watch(authProvider.notifier)
              .saveAuthInfo(accessToken: loginResponseDto.accessToken);

          if (isSuccess) {
            isLoading.value = false;
            final permission = ref.watch(galleryPermissionNotifier);
            final isBeta = Store.isBetaTimelineEnabled;
            if (!isBeta && (permission.isGranted || permission.isLimited)) {
              unawaited(ref.watch(backupProvider.notifier).resumeBackup());
            }
            if (isBeta) {
              await ref.read(galleryPermissionNotifier.notifier).requestGalleryPermission();
              unawaited(handleSyncFlow());
              unawaited(context.replaceRoute(const TabShellRoute()));
              return;
            }
            unawaited(context.replaceRoute(const TabControllerRoute()));
          }
        } catch (error, stack) {
          log.severe('Error logging in with OAuth: $error', stack);

          ImmichToast.show(
            context: context,
            msg: error.toString(),
            toastType: ToastType.error,
            gravity: ToastGravity.TOP,
          );
        } finally {
          isLoading.value = false;
        }
      } else {
        ImmichToast.show(
          context: context,
          msg: "login_form_failed_get_oauth_server_disable".tr(),
          toastType: ToastType.info,
          gravity: ToastGravity.TOP,
        );
        isLoading.value = false;
        return;
      }
    }

    buildSelectServer() {
      const buttonRadius = 25.0;
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ServerEndpointInput(
            controller: serverEndpointController,
            focusNode: serverEndpointFocusNode,
            onSubmit: getServerAuthSettings,
          ),
          const SizedBox(height: 18),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: const RoundedRectangleBorder(
                      borderRadius: BorderRadius.only(
                        topLeft: Radius.circular(buttonRadius),
                        bottomLeft: Radius.circular(buttonRadius),
                      ),
                    ),
                  ),
                  onPressed: () => context.pushRoute(const SettingsRoute()),
                  icon: const Icon(Icons.settings_rounded),
                  label: const Text(""),
                ),
              ),
              const SizedBox(width: 1),
              Expanded(
                flex: 3,
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: const RoundedRectangleBorder(
                      borderRadius: BorderRadius.only(
                        topRight: Radius.circular(buttonRadius),
                        bottomRight: Radius.circular(buttonRadius),
                      ),
                    ),
                  ),
                  onPressed: isLoadingServer.value ? null : getServerAuthSettings,
                  icon: const Icon(Icons.arrow_forward_rounded),
                  label: const Text('next', style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold)).tr(),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          if (isLoadingServer.value) const LoadingIcon(),
        ],
      );
    }

    buildVersionCompatWarning() {
      checkVersionMismatch();

      if (warningMessage.value == null) {
        return const SizedBox.shrink();
      }

      return Padding(
        padding: const EdgeInsets.only(bottom: 8.0),
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: context.isDarkTheme ? Colors.red.shade700 : Colors.red.shade100,
            borderRadius: const BorderRadius.all(Radius.circular(8)),
            border: Border.all(color: context.isDarkTheme ? Colors.red.shade900 : Colors.red[200]!),
          ),
          child: Text(warningMessage.value!, textAlign: TextAlign.center),
        ),
      );
    }

    buildLogin() {
      return AutofillGroup(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            buildVersionCompatWarning(),
            Text(
              sanitizeUrl(serverEndpointController.text),
              style: context.textTheme.displaySmall,
              textAlign: TextAlign.center,
            ),
            if (isPasswordLoginEnable.value) ...[
              const SizedBox(height: 18),
              EmailInput(
                controller: emailController,
                focusNode: emailFocusNode,
                onSubmit: passwordFocusNode.requestFocus,
              ),
              const SizedBox(height: 8),
              PasswordInput(controller: passwordController, focusNode: passwordFocusNode, onSubmit: login),
            ],

            // Note: This used to have an AnimatedSwitcher, but was removed
            // because of https://github.com/flutter/flutter/issues/120874
            isLoading.value
                ? const LoadingIcon()
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const SizedBox(height: 18),
                      if (isPasswordLoginEnable.value) LoginButton(onPressed: login),
                      if (isOauthEnable.value) ...[
                        if (isPasswordLoginEnable.value)
                          Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 16.0),
                            child: Divider(color: context.isDarkTheme ? Colors.white : Colors.black),
                          ),
                        OAuthLoginButton(
                          serverEndpointController: serverEndpointController,
                          buttonLabel: oAuthButtonLabel.value,
                          isLoading: isLoading,
                          onPressed: oAuthLogin,
                        ),
                      ],
                    ],
                  ),
            if (!isOauthEnable.value && !isPasswordLoginEnable.value) Center(child: const Text('login_disabled').tr()),
            const SizedBox(height: 12),
            TextButton.icon(
              icon: const Icon(Icons.arrow_back),
              onPressed: () => serverEndpoint.value = null,
              label: const Text('back').tr(),
            ),
            const SizedBox(height: 8),
            TextButton.icon(
              icon: const Icon(Icons.swap_horiz, size: 18),
              style: TextButton.styleFrom(foregroundColor: context.colorScheme.onSurfaceSecondary),
              onPressed: () => _showChangeRyvieDialog(context, ref),
              label: Text(
                'Changer de Ryvie',
                style: TextStyle(fontSize: 13, color: context.colorScheme.onSurfaceSecondary),
              ),
            ),
          ],
        ),
      );
    }

    final serverSelectionOrLogin = serverEndpoint.value == null ? buildSelectServer() : buildLogin();

    return LayoutBuilder(
      builder: (context, constraints) {
        return SingleChildScrollView(
          child: Center(
            child: Container(
              constraints: const BoxConstraints(maxWidth: 300),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  SizedBox(height: constraints.maxHeight / 5),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      GestureDetector(
                        onDoubleTap: () => populateTestLoginInfo(),
                        onLongPress: () => populateTestLoginInfo1(),
                        child: RotationTransition(
                          turns: logoAnimationController,
                          child: const ImmichLogo(heroTag: 'logo'),
                        ),
                      ),
                      const Padding(padding: EdgeInsets.only(top: 8.0, bottom: 16), child: ImmichTitleText()),
                    ],
                  ),

                  // Note: This used to have an AnimatedSwitcher, but was removed
                  // because of https://github.com/flutter/flutter/issues/120874
                  Form(key: loginFormKey, child: serverSelectionOrLogin),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}
