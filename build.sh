#!/bin/bash
# Cross-platform build script for Chatterbox

echo "Installing dependencies..."
pip install pyinstaller pycryptodome netifaces

echo "Building Chatterbox executable..."

# Detect platform and build accordingly
case "$OSTYPE" in
  msys*|cygwin*|win*)
    echo "Building for Windows..."
    pyinstaller --onefile --windowed --name chatterbox chatterbox.py
    echo "Windows executable created: dist/chatterbox.exe"
    ;;
  darwin*)
    echo "Building for macOS..."
    pyinstaller --onefile --windowed --name chatterbox-mac chatterbox.py
    echo "macOS executable created: dist/chatterbox-mac"
    ;;
  linux*)
    echo "Building for Linux..."
    pyinstaller --onefile --windowed --name chatterbox-linux chatterbox.py
    echo "Linux executable created: dist/chatterbox-linux"
    ;;
  *)
    echo "Unknown platform: $OSTYPE"
    echo "Building generic executable..."
    pyinstaller --onefile --windowed --name chatterbox chatterbox.py
    ;;
esac

echo ""
echo "Build complete!"
echo "The executable is in the 'dist/' directory"
echo ""
echo "To run the application:"
echo "  ./dist/chatterbox*"