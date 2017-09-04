
Debian
====================
This directory contains files used to package purad/pura-qt
for Debian-based Linux systems. If you compile purad/pura-qt yourself, there are some useful files here.

## pura: URI support ##


pura-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install pura-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your pura-qt binary to `/usr/bin`
and the `../../share/pixmaps/pura128.png` to `/usr/share/pixmaps`

pura-qt.protocol (KDE)

