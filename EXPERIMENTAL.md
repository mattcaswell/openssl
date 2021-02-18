EXPERIMENTAL BUILD
==================

The code you found is not an official variant and will most likely
never be.  It's an experiment to see how OpenSSL 1.1.1 programs build
against OpenSSL 3.0 libraries.

This is done as a bypass around OpenSSL's build and test system:

-   The experiment is built using cmake, and it builds the following:

    -   The OpenSSL command:

        -   apps/openssl

    -   Some engine modules:

        -   engines/afalgeng.so
        -   engines/dasync.so
        -   engines/ossltest.so

    -   All the fuzz testers:

        -   fuzz/asn1parse-test
        -   fuzz/asn1-test
        -   fuzz/bignum-test
        -   fuzz/bndiv-test
        -   fuzz/client-test
        -   fuzz/cms-test
        -   fuzz/conf-test
        -   fuzz/crl-test
        -   fuzz/ct-test
        -   fuzz/server-test
        -   fuzz/x509-test

    -   A majority of our test programs:

        -   test/aborttest
        -   test/afalgtest
        -   test/asn1_decode_test
        -   test/asn1_encode_test
        -   test/asn1_string_table_test
        -   test/asn1_time_test
        -   test/asynciotest
        -   test/asynctest
        -   test/bad_dtls_test
        -   test/bftest
        -   test/bio_callback_test
        -   test/bio_enc_test
        -   test/bio_memleak_test
        -   test/bioprinttest
        -   test/bntest
        -   test/casttest
        -   test/cipherbytes_test
        -   test/cipherlist_test
        -   test/ciphername_test
        -   test/clienthellotest
        -   test/CMakeFiles
        -   test/cmake_install.cmake
        -   test/cmsapitest
        -   test/conf_include_test
        -   test/constant_time_test
        -   test/crltest
        -   test/ct_test
        -   test/d2i_test
        -   test/danetest
        -   test/default-and-legacy.cnf
        -   test/destest
        -   test/dhtest
        -   test/dsa_no_digest_size_test
        -   test/dsatest
        -   test/dtls_mtu_test
        -   test/dtlstest
        -   test/dtlsv1listentest
        -   test/ecdsatest
        -   test/ecstresstest
        -   test/ectest
        -   test/enginetest
        -   test/errtest
        -   test/evp_extra_test
        -   test/evp_test
        -   test/exdatatest
        -   test/exptest
        -   test/fatalerrtest
        -   test/gmdifftest
        -   test/gosttest
        -   test/hmactest
        -   test/ideatest
        -   test/igetest
        -   test/lhash_test
        -   test/liblibtestutil.a
        -   test/libssltestlib.a
        -   test/Makefile
        -   test/md2test
        -   test/mdc2_internal_test
        -   test/mdc2test
        -   test/memleaktest
        -   test/ocspapitest
        -   test/packettest
        -   test/pbelutest
        -   test/pemtest
        -   test/pkey_meth_kdf_test
        -   test/pkey_meth_test
        -   test/rc2test
        -   test/rc4test
        -   test/rc5test
        -   test/recordlentest
        -   test/rsa_complex
        -   test/rsa_mp_test
        -   test/rsa_test
        -   test/sanitytest
        -   test/secmemtest
        -   test/servername_test
        -   test/srptest
        -   test/sslapitest
        -   test/sslbuffertest
        -   test/ssl_cert_table_internal_test
        -   test/sslcorrupttest
        -   test/ssl_ctx_test
        -   test/ssl_test
        -   test/ssl_test_ctx_test
        -   test/ssltest_old
        -   test/stack_test
        -   test/sysdefaulttest
        -   test/test_test
        -   test/time_offset_test
        -   test/tls13ccstest
        -   test/uitest
        -   test/v3ext
        -   test/v3nametest
        -   test/verify_extra_test
        -   test/versions
        -   test/x509aux
        -   test/x509_check_cert_pkey_test
        -   test/x509_dup_cert_test
        -   test/x509_time_test

-   The experiment is tested with the 1.1.1 test suite (all the test
    recipes, i.e. test/recipes/*.t), using the standard perl test
    harness (the command 'prove') combined with a plugin to get the
    necessary environment variables in place.

Limitations
-----------

This experiment *must* be built against an OpenSSL 3.0 build
directory, *not* against an OpenSSL 3.0 installation.

This experiment doesn't have all the fancy configuration options of
OpenSSL's normal configuration system.  It expects that OpenSSL 3.0 is
built with the default configuration, i.e. it doesn't try to check if
anything has been enabled or disabled.  If OpenSSL 3.0 has had certain
features disabled, the build of this experiment is likely to fail.

How to build
------------

IT IS HIGHLY RECOMMENDED TO BUILD IN A SEPARATE DIRECTORY

In the text that follows, we use the shell variable $SRCDIR as a
placeholder for the OpenSSL 1.1.1 source directory.

0.  Preparation - create that build directory and move into it

        mkdir _build
        cd _build

1.  Configuration

        # It's assume that you stand in the build directory
        cmake -DCMAKE_MODULE_PATH=$SRCDIR/util/cmake/Modules \
              -DCMAKE_PREFIX_PATH=/PATH/TO/OPENSSL3/BUILD \
              -S $SRCDIR -B .

    You will have to replace `/PATH/TO/OPENSSL3/BUILD` with the
    correct OpenSSL 3.0 build directory.

    You may want to add other cmake options.  For example, if you want
    a debug build, please consider adding `-DCMAKE_BUILD_TYPE=Debug`
    to the cmake command line above.

    There are a few additional options available that may be useful:

    -   `-DENABLE_ASAN`

        This matches OpenSSL's `enable-asan` option.  You may want to
        use this if OpenSSL 3.0 was build with that configuration
        option.

    -   `-DENABLE_UBSAN`

        This matches OpenSSL's `enable-ubsan` option.  You may want to
        use this if OpenSSL 3.0 was build with that configuration
        option.

2.  Build

        # It's assume that you stand in the build directory
        cmake --build .

3.  Test

        # It's assume that you stand in the build directory
        make test

    If you want a verbose test, please consider adding `VERBOSE=1`:

        make VERBOSE=1 test

External code used
------------------

The following files from other sources have been copied (as permitted
by the author's license on those files):

-   util/cmake/Modules/FindOpenSSL.cmake

    This is a hack on top of cmake's own FindOpenSSL.cmake, that makes
    it possible to build anything against an OpenSSL build tree.  All
    it requires to detect it is the presence of the file configdata.pm

    Origin: https://github.com/levitte/openssl-extras.git,
    cmake/Modules/FindOpenSSL.cmake

-   util/perl/WrapOpenSSL.pm

    This is the 'prove' plugin, which essentially performs the
    necessary preparations that test/run_tests.pl normally does.

    Origin: https://github.com/levitte/openssl-extras.git,
    perl/lib/WrapOpenSSL.pm
