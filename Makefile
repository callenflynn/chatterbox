# Build Script for Chatterbox Desktop App

# For Windows
build-windows:
	pip install pyinstaller
	pyinstaller --onefile --windowed --name chatterbox --icon=assets/icon.ico chatterbox.py
	@echo "Windows executable created in dist/chatterbox.exe"

# For macOS
build-mac:
	pip install pyinstaller
	pyinstaller --onefile --windowed --name chatterbox-mac --icon=assets/icon.icns chatterbox.py
	@echo "macOS executable created in dist/chatterbox-mac"

# For Linux
build-linux:
	pip install pyinstaller
	pyinstaller --onefile --windowed --name chatterbox-linux chatterbox.py
	@echo "Linux executable created in dist/chatterbox-linux"

# Install dependencies
install:
	pip install -r requirements.txt

# Run from source
run:
	python chatterbox.py

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.spec __pycache__/

# Package for distribution
package: clean build-windows
	mkdir -p releases
	cp dist/chatterbox.exe releases/
	cp README.md releases/
	@echo "Package ready in releases/"

.PHONY: build-windows build-mac build-linux install run clean package