# Platforms and packages

The initial validation target is **Python 3.12 on Ubuntu 22.04/24.04 and Debian 12**. Local development, live screenshot capture, tests and package smoke test were performed on the current Ubuntu 24.04 environment; CI is configured for Ubuntu 22.04/24.04 but remains unverified until the repository is published and workflow executes.

PySide6 desktop display needs Linux Qt platform libraries, including XCB and OpenGL/EGL support. A real graphical session is preferred. For CI or screenshots, `QT_QPA_PLATFORM=offscreen` works if the Qt offscreen plugin is present. An unsigned PyInstaller onedir archive is produced by `scripts/build_linux.sh`; extract it and run `Linux-Security-Auditor/Linux-Security-Auditor`. Build on a compatible distribution when distributing because glibc and Qt system library versions vary. No native Windows package is claimed or built.
