# DSSL library: network capture and SSL decryption toolkit

[![Build Status](https://travis-ci.org/Correlsense/libdssl.svg?branch=master)](https://travis-ci.org/Correlsense/libdssl)

To view the installation documentation, load docs/index.html into your browser.

----------------------------------------------
### Introduction

This fork contains improvements to the original code (by Atomic Labs, Inc.),<br />
some for our internal use (but may still be useful to others) and some will benefit the community

 * _multiplatform support_<br />
   this fork has been built and tested on the following platforms
   * Solaris 8/9 sparc
   * Solaris 10 i386/sparc
   * AIX 5.3/6.1 ppc
   * Linux x86/x86_64/ppc
   * Windows x86/x86_64
   * HPUX parisc/ia64

 * _Support for TLS v1.2+_

----------------------------------------------
### Build and Runtime Prerequisites

 * openssl
 * libpcap

----------------------------------------------
### Notes

* SSL decryption is not possible when DHE (Diffie-Hellman key Exchange, or ephemeral keys) is used

----------------------------------------------

[![Correlsense](http://www.correlsense.com/newsite2/wp-content/uploads/logo-cs.png)](http://www.correlsense.com)
