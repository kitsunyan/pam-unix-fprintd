# pam-unix-fprintd

A modified pam_unix with fprintd support which allows you both enter password and verify fingerprint.

## Building and Installing

The `fprintd` package,`glib` library and GNU Autotools should be installed.

Run `./autogen.sh && ./configure && make && sudo make install` to build and install pam-unix-fprintd to your system.

## Installing and Configuration

PAM module is named `pam_unix_fprintd.so` and supports authentication management. So you should just replace `auth required pam_unix.so` with `auth required pam_unix_fprintd.so` in `/etc/pam.d/system-auth` file.

This module supports all parameters which `pam_unix.so` supports.

## License

This program is licensed with GPLv2.
