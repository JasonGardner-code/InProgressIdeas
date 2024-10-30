#!/bin/bash

# Find all .apk files in the current directory
apk_files=$(find . -type f -name "*.apk")

# Check if any APK files are found
if [ -z "$apk_files" ]; then
  echo "No APK files found in the current directory."
  exit 1
fi

# Install each APK found
for apk in $apk_files; do
  echo "Installing $apk..."
  adb install "$apk"
  
  # Check if the installation was successful
  if [ $? -eq 0 ]; then
    echo "Successfully installed $apk."
  else
    echo "Failed to install $apk."
  fi
done

echo "All APK installations complete."
