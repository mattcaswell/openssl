#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test;
use OpenSSL::Test::Simple;

plan skip_all => "Test doesn't work in CMAKE build" if $ENV{OPENSSL_CMAKE_BUILD};

simple_test("test_mdc2", "mdc2test", "mdc2");
