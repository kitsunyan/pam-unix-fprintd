#!/bin/sh
autoreconf -v --force --install
[ "$NOCONFIGURE" ] || exec ./configure "$@"
