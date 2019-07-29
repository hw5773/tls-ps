<!--
.. title: Download
.. slug: download
.. date: 2019-04-30 13:12:00 UTC+1
.. tags: tag
.. category: category
.. link: link
.. description:
.. type: text
-->

# Source

* [mosquitto-1.6.3.tar.gz](https://mosquitto.org/files/source/mosquitto-1.6.3.tar.gz) (319kB) ([GPG signature](https://mosquitto.org/files/source/mosquitto-1.6.3.tar.gz.asc))
* [Git source code repository](https://github.com/eclipse/mosquitto) (github.com)

Older downloads are available at [https://mosquitto.org/files/](../files/)

# Binary Installation

The binary packages listed below are supported by the Mosquitto project. In many
cases Mosquitto is also available directly from official Linux/BSD
distributions.

## Windows

* [mosquitto-1.6.3-install-windows-x64.exe](https://mosquitto.org/files/binary/win64/mosquitto-1.6.3-install-windows-x64.exe) (~1.4 MB) (64-bit build, Windows Vista and up, built with Visual Studio Community 2017)
* [mosquitto-1.6.3-install-windows-x32.exe](https://mosquitto.org/files/binary/win32/mosquitto-1.6.2-install-windows-x86.exe) (~1.4 MB) (32-bit build, Windows Vista and up, built with Visual Studio Community 2017)

See also readme-windows.txt after installing.

## Mac
Mosquitto can be installed from the homebrew project. See
[brew.sh](https://brew.sh/) and then use `brew install mosquitto`

## Linux distributions with snap support

* `snap install mosquitto`

## Debian
* Mosquitto is now in Debian proper. There will be a short delay between a new
  release and it appearing in Debian as part of the normal Debian procedures.
* There are also Debian repositories provided by the mosquitto project, as
  described at <https://mosquitto.org/2013/01/mosquitto-debian-repository>

## Raspberry Pi
Mosquitto is available through the main repository.

There are also Debian repositories provided by the mosquitto project, as
described at <https://mosquitto.org/2013/01/mosquitto-debian-repository/>

## Ubuntu
Mosquitto is available in the Ubuntu repositories so you can install as with
any other package. If you are on an earlier version of Ubuntu or want a more
recent version of mosquitto, add the [mosquitto-dev
PPA](https://launchpad.net/%7Emosquitto-dev/+archive/mosquitto-ppa/) to your
repositories list - see the link for details. mosquitto can then be installed
from your package manager.

* `sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa`
* `sudo apt-get update`