# gotify-archsec [![Build Status](https://travis-ci.org/buckket/gotify-archsec.svg?branch=master)](https://travis-ci.org/buckket/gotify-archsec)

A plugin for [gotify/server](https://github.com/gotify/server) which polls the [Arch Linux Security](https://security.archlinux.org/) 
[feed](https://security.archlinux.org/advisory/feed.atom) for new advisories and sends out messages when needed.

This plugin can easily be modified to watch any other RSS/Atom feed for new entries and act upon it.

## Building

For building the plugin gotify/build docker images are used to ensure compatibility with 
[gotify/server](https://github.com/gotify/server).

`GOTIFY_VERSION` can be a tag, commit or branch from the gotify/server repository.

This command builds the plugin for amd64, arm-7 and arm64. 
The resulting shared object will be compatible with gotify/server version 2.0.5.
```bash
$ make GOTIFY_VERSION="v2.0.5" FILE_SUFFIX="for-gotify-v2.0.5" build
```

## Installation

Copy built shared object to the gotify plugin directory and restart gotify.

## Configuration

- `refresh_interval`: Polling interval in seconds

## License

GNU GPLv3+
