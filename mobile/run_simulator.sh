#!/bin/bash

# Script pour lancer rPictures sur le simulateur iPhone 17 Pro
# avec les logs de récupération des infos tunnel

echo "🚀 Lancement de rPictures sur iPhone 17 Pro..."
echo ""

# ID du simulateur iPhone 17 Pro
SIMULATOR_ID="9F02DEFC-40C1-4CD8-8079-D318E991979E"

echo "📦 Récupération des dépendances Flutter..."
flutter pub get > /dev/null 2>&1

echo "✅ Dépendances récupérées"
echo ""

# Aller dans le dossier ios
cd ios

echo "🔨 Build de l'application..."
echo "⏳ Cela peut prendre quelques minutes..."
echo ""

# Build avec xcodebuild
xcodebuild -workspace Runner.xcworkspace \
  -scheme Runner \
  -configuration Debug \
  -sdk iphonesimulator \
  -destination "id=$SIMULATOR_ID" \
  -derivedDataPath build \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO

if [ $? -ne 0 ]; then
  echo "❌ Erreur lors du build"
  exit 1
fi

echo ""
echo "✅ Build terminé"
echo ""

# Installer l'app sur le simulateur
echo "📲 Installation de l'app sur le simulateur..."
xcrun simctl install $SIMULATOR_ID build/Build/Products/Debug-iphonesimulator/rPictures-Debug.app

if [ $? -ne 0 ]; then
  echo "❌ Erreur lors de l'installation"
  exit 1
fi

echo "✅ Installation terminée"
echo ""

# Lancer l'app avec les logs
echo "🚀 Lancement de l'app..."
xcrun simctl launch --console $SIMULATOR_ID com.ryvie.julesmaison.rpictures 2>&1 | grep -E "(RyvieApiService|SmartUrlSelector|ryvieId|tunnelHost|publicUrl|setupKey|Token JWT|Récupération|authenticate|AuthNotifier)" --color=always
