#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test;

plan skip_all => "Test doesn't work in CMAKE build" if $ENV{OPENSSL_CMAKE_BUILD};

plan tests => 2;
setup("test_rand");

ok(run(test(["drbgtest"])));
ok(run(test(["drbg_cavs_test"])));
