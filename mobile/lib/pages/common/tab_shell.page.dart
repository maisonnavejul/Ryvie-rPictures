import 'dart:async';

import 'package:auto_route/auto_route.dart';
import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:immich_mobile/constants/constants.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/domain/models/timeline.model.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/domain/utils/event_stream.dart';
import 'package:immich_mobile/extensions/build_context_extensions.dart';
import 'package:immich_mobile/presentation/pages/search/paginated_search.provider.dart';
import 'package:immich_mobile/providers/background_sync.provider.dart';
import 'package:immich_mobile/providers/connection_status.provider.dart';
import 'package:immich_mobile/providers/backup/drift_backup.provider.dart';
import 'package:immich_mobile/providers/haptic_feedback.provider.dart';
import 'package:immich_mobile/providers/infrastructure/album.provider.dart';
import 'package:immich_mobile/providers/infrastructure/memory.provider.dart';
import 'package:immich_mobile/providers/infrastructure/people.provider.dart';
import 'package:immich_mobile/providers/infrastructure/readonly_mode.provider.dart';
import 'package:immich_mobile/providers/search/search_input_focus.provider.dart';
import 'package:immich_mobile/providers/tab.provider.dart';
import 'package:immich_mobile/providers/timeline/multiselect.provider.dart';
import 'package:immich_mobile/providers/user.provider.dart';
import 'package:immich_mobile/routing/router.dart';
import 'package:immich_mobile/widgets/common/connection_error_banner.dart';
import 'package:immich_mobile/providers/server_health_check.provider.dart';

@RoutePage()
class TabShellPage extends ConsumerStatefulWidget {
  const TabShellPage({super.key});

  @override
  ConsumerState<TabShellPage> createState() => _TabShellPageState();
}

class _TabShellPageState extends ConsumerState<TabShellPage> {
  bool _backupKickRunning = false;
  ProviderSubscription<ConnectionStatusState>? _connectionSubscription;

  @override
  void initState() {
    super.initState();
    // Lancer un health check unique quand l'utilisateur arrive sur la page principale
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(serverHealthCheckProvider).performHealthCheck();
      _startBackupIfEnabled();
    });

    // Si le serveur n'était pas joignable au lancement, relancer la sync +
    // backup dès que la connexion est rétablie.
    _connectionSubscription = ref.listenManual<ConnectionStatusState>(connectionStatusProvider, (previous, next) {
      if (previous?.status != ConnectionStatus.connected && next.status == ConnectionStatus.connected) {
        _startBackupIfEnabled();
      }
    });
  }

  /// Même comportement que la page Sauvegarde : sync distante → refresh des
  /// compteurs → top-up de la queue d'upload. Sans ça, le backup ne démarre
  /// que lorsque l'utilisateur ouvre manuellement la page Sauvegarde.
  Future<void> _startBackupIfEnabled() async {
    if (_backupKickRunning) return;
    if (!Store.get(StoreKey.enableBackup, false)) return;
    final currentUser = ref.read(currentUserProvider);
    if (currentUser == null) return;

    _backupKickRunning = true;
    try {
      final notifier = ref.read(driftBackupProvider.notifier);
      await notifier.getBackupStatus(currentUser.id);
      if (!mounted) return;

      if (!ref.read(driftBackupProvider).isSyncing) {
        notifier.updateSyncing(true);
        await ref.read(backgroundSyncProvider).syncRemote();
        if (!mounted) return;
        notifier.updateSyncing(false);
        await notifier.getBackupStatus(currentUser.id);
      }

      if (!mounted) return;
      final state = ref.read(driftBackupProvider);
      if (state.effectiveRemainderCount > 0 && !state.isStartingBackup) {
        await notifier.continueBackup(currentUser.id);
      }
    } finally {
      _backupKickRunning = false;
    }
  }

  @override
  void dispose() {
    _connectionSubscription?.close();
    // Arrêter le retry loop quand l'utilisateur quitte la page
    ref.read(serverHealthCheckProvider).stopRetryLoop();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isScreenLandscape = context.orientation == Orientation.landscape;
    final isReadonlyModeEnabled = ref.watch(readonlyModeProvider);

    final navigationDestinations = [
      NavigationDestination(
        label: 'photos'.tr(),
        icon: const Icon(Icons.photo_library_outlined),
        selectedIcon: Icon(Icons.photo_library, color: context.primaryColor),
      ),
      NavigationDestination(
        label: 'search'.tr(),
        icon: const Icon(Icons.search_rounded),
        selectedIcon: Icon(Icons.search, color: context.primaryColor),
        enabled: !isReadonlyModeEnabled,
      ),
      NavigationDestination(
        label: 'albums'.tr(),
        icon: const Icon(Icons.photo_album_outlined),
        selectedIcon: Icon(Icons.photo_album_rounded, color: context.primaryColor),
        enabled: !isReadonlyModeEnabled,
      ),
      NavigationDestination(
        label: 'library'.tr(),
        icon: const Icon(Icons.space_dashboard_outlined),
        selectedIcon: Icon(Icons.space_dashboard_rounded, color: context.primaryColor),
        enabled: !isReadonlyModeEnabled,
      ),
    ];

    Widget navigationRail(TabsRouter tabsRouter) {
      return NavigationRail(
        destinations: navigationDestinations
            .map(
              (e) => NavigationRailDestination(
                icon: e.icon,
                label: Text(e.label),
                selectedIcon: e.selectedIcon,
                disabled: !e.enabled,
              ),
            )
            .toList(),
        onDestinationSelected: (index) => _onNavigationSelected(tabsRouter, index, ref),
        selectedIndex: tabsRouter.activeIndex,
        labelType: NavigationRailLabelType.all,
        groupAlignment: 0.0,
      );
    }

    return AutoTabsRouter(
      routes: const [MainTimelineRoute(), DriftSearchRoute(), DriftAlbumsRoute(), DriftLibraryRoute()],
      duration: const Duration(milliseconds: 600),
      transitionBuilder: (context, child, animation) => FadeTransition(opacity: animation, child: child),
      builder: (context, child) {
        final tabsRouter = AutoTabsRouter.of(context);
        return PopScope(
          canPop: tabsRouter.activeIndex == 0,
          onPopInvokedWithResult: (didPop, _) => !didPop ? tabsRouter.setActiveIndex(0) : null,
          child: Scaffold(
            resizeToAvoidBottomInset: false,
            body: Column(
              children: [
                const ConnectionErrorBanner(),
                Expanded(
                  child: isScreenLandscape
                      ? Row(
                          children: [
                            navigationRail(tabsRouter),
                            const VerticalDivider(),
                            Expanded(child: child),
                          ],
                        )
                      : child,
                ),
              ],
            ),
            bottomNavigationBar: _BottomNavigationBar(tabsRouter: tabsRouter, destinations: navigationDestinations),
          ),
        );
      },
    );
  }
}

void _onNavigationSelected(TabsRouter router, int index, WidgetRef ref) {
  // On Photos page menu tapped
  if (router.activeIndex == kPhotoTabIndex && index == kPhotoTabIndex) {
    EventStream.shared.emit(const ScrollToTopEvent());
  }

  if (index == kPhotoTabIndex) {
    ref.invalidate(driftMemoryFutureProvider);
  }

  if (router.activeIndex != kSearchTabIndex && index == kSearchTabIndex) {
    ref.read(searchPreFilterProvider.notifier).clear();
  }

  // On Search page tapped
  if (router.activeIndex == kSearchTabIndex && index == kSearchTabIndex) {
    ref.read(searchInputFocusProvider).requestFocus();
  }

  // Album page
  if (index == kAlbumTabIndex) {
    ref.read(remoteAlbumProvider.notifier).refresh();
  }

  // Library page
  if (index == kLibraryTabIndex) {
    ref.invalidate(localAlbumProvider);
    ref.invalidate(driftGetAllPeopleProvider);
  }

  ref.read(hapticFeedbackProvider.notifier).selectionClick();
  router.setActiveIndex(index);
  ref.read(tabProvider.notifier).state = TabEnum.values[index];
}

class _BottomNavigationBar extends ConsumerStatefulWidget {
  const _BottomNavigationBar({required this.tabsRouter, required this.destinations});

  final List<Widget> destinations;
  final TabsRouter tabsRouter;

  @override
  ConsumerState createState() => _BottomNavigationBarState();
}

class _BottomNavigationBarState extends ConsumerState<_BottomNavigationBar> {
  bool hideNavigationBar = false;
  StreamSubscription? _eventSubscription;

  @override
  void initState() {
    super.initState();
    _eventSubscription = EventStream.shared.listen<MultiSelectToggleEvent>(_onEvent);
  }

  void _onEvent(MultiSelectToggleEvent event) {
    setState(() {
      hideNavigationBar = event.isEnabled;
    });
  }

  @override
  void dispose() {
    _eventSubscription?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isScreenLandscape = context.orientation == Orientation.landscape;

    if (isScreenLandscape || hideNavigationBar) {
      return const SizedBox.shrink();
    }

    return NavigationBar(
      selectedIndex: widget.tabsRouter.activeIndex,
      onDestinationSelected: (index) => _onNavigationSelected(widget.tabsRouter, index, ref),
      destinations: widget.destinations,
    );
  }
}
