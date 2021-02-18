set(LIBTESTUTIL_SOURCE
  testutil/basic_output.c testutil/output_helpers.c
  testutil/driver.c testutil/tests.c testutil/cb.c testutil/stanza.c
  testutil/format_output.c testutil/tap_bio.c
  testutil/test_cleanup.c testutil/main.c testutil/testutil_init.c
  testutil/random.c)
add_library(libtestutil STATIC ${LIBTESTUTIL_SOURCE})
target_include_directories(libtestutil PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(libtestutil INTERFACE ${OPENSSL_CRYPTO_LIBRARIES})

set(SSLTESTLIB_SOURCE
  ssltestlib.c ssl_test_ctx.c handshake_helper.c)
add_library(ssltestlib STATIC ${SSLTESTLIB_SOURCE})
target_include_directories(ssltestlib PUBLIC .. ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ssltestlib INTERFACE ${OPENSSL_LIBRARIES})

add_executable(versions versions.c)
target_include_directories(versions PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(versions PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(aborttest aborttest.c)
target_include_directories(aborttest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(aborttest PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(sanitytest sanitytest.c)
target_include_directories(sanitytest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(sanitytest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(rsa_complex rsa_complex.c)
target_include_directories(rsa_complex PRIVATE ${OPENSSL_INCLUDE_DIR})

add_executable(test_test test_test.c)
target_include_directories(test_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(test_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(exdatatest exdatatest.c)
target_include_directories(exdatatest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(exdatatest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(bntest bntest.c)
target_include_directories(bntest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bntest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(ectest ectest.c)
target_include_directories(ectest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ectest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(ecstresstest ecstresstest.c)
target_include_directories(ecstresstest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ecstresstest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(ecdsatest ecdsatest.c)
target_include_directories(ecdsatest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ecdsatest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(gmdifftest gmdifftest.c)
target_include_directories(gmdifftest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(gmdifftest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(pbelutest pbelutest.c)
target_include_directories(pbelutest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pbelutest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(ideatest ideatest.c)
target_include_directories(ideatest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ideatest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(md2test md2test.c)
target_include_directories(md2test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(md2test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(hmactest hmactest.c)
target_include_directories(hmactest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(hmactest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(rc2test rc2test.c)
target_include_directories(rc2test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(rc2test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(rc4test rc4test.c)
target_include_directories(rc4test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(rc4test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(rc5test rc5test.c)
target_include_directories(rc5test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(rc5test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})


add_executable(destest destest.c)
target_include_directories(destest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(destest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

# Skip mdc2test, it does internal things to the MDC2 things where a ctrl
# function would normally be used
#add_executable(mdc2test mdc2test.c)
#target_include_directories(mdc2test PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries(mdc2test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})


add_executable(dhtest dhtest.c)
target_include_directories(dhtest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dhtest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(enginetest enginetest.c)
target_include_directories(enginetest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(enginetest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(casttest casttest.c)
target_include_directories(casttest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(casttest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})


add_executable(bftest bftest.c)
target_include_directories(bftest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bftest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

# This program includes e_os.h, let's hope the 1.1.1 one is good enough
add_executable(ssltest_old ssltest_old.c)
target_compile_definitions(ssltest_old PRIVATE OPENSSL_UNISTD=<unistd.h>)
target_include_directories(ssltest_old PRIVATE .. ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ssltest_old PRIVATE ${OPENSSL_LIBRARIES})

add_executable(dsatest dsatest.c)
target_include_directories(dsatest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dsatest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(dsa_no_digest_size_test dsa_no_digest_size_test.c)
target_include_directories(dsa_no_digest_size_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dsa_no_digest_size_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(exptest exptest.c)
target_include_directories(exptest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(exptest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(rsa_test rsa_test.c)
target_include_directories(rsa_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(rsa_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(rsa_mp_test rsa_mp_test.c)
target_include_directories(rsa_mp_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(rsa_mp_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(fatalerrtest fatalerrtest.c)
target_include_directories(fatalerrtest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(fatalerrtest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(tls13ccstest tls13ccstest.c)
target_include_directories(tls13ccstest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(tls13ccstest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(evp_test evp_test.c)
target_include_directories(evp_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(evp_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(evp_extra_test evp_extra_test.c)
target_include_directories(evp_extra_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(evp_extra_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(igetest igetest.c)
target_include_directories(igetest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(igetest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(v3nametest v3nametest.c)
target_include_directories(v3nametest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(v3nametest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(crltest crltest.c)
target_include_directories(crltest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(crltest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(v3ext v3ext.c)
target_include_directories(v3ext PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(v3ext PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(danetest danetest.c)
target_include_directories(danetest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(danetest PRIVATE libtestutil ${OPENSSL_LIBRARIES})

add_executable(constant_time_test constant_time_test.c)
target_include_directories(constant_time_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(constant_time_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(verify_extra_test verify_extra_test.c)
target_include_directories(verify_extra_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(verify_extra_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(clienthellotest clienthellotest.c)
target_include_directories(clienthellotest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(clienthellotest PRIVATE libtestutil ${OPENSSL_LIBRARIES})

add_executable(bad_dtls_test bad_dtls_test.c)
target_include_directories(bad_dtls_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bad_dtls_test PRIVATE libtestutil ${OPENSSL_LIBRARIES})

add_executable(packettest packettest.c)
target_include_directories(packettest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(packettest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(asynctest asynctest.c)
target_include_directories(asynctest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asynctest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(secmemtest secmemtest.c)
target_include_directories(secmemtest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(secmemtest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(srptest srptest.c)
target_include_directories(srptest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(srptest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(memleaktest memleaktest.c)
target_include_directories(memleaktest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(memleaktest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(stack_test stack_test.c)
target_include_directories(stack_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(stack_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(lhash_test lhash_test.c)
target_include_directories(lhash_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(lhash_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(dtlsv1listentest dtlsv1listentest.c)
target_include_directories(dtlsv1listentest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dtlsv1listentest PRIVATE libtestutil ${OPENSSL_SSL_LIBRARIES})

add_executable(ct_test ct_test.c)
target_include_directories(ct_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ct_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

#add_executable(threadstest threadstest.c)
#target_include_directories(threadstest PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries(threadstest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(afalgtest afalgtest.c)
target_include_directories(afalgtest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(afalgtest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(d2i_test d2i_test.c)
target_include_directories(d2i_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(d2i_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(ssl_test_ctx_test ssl_test_ctx_test.c)
target_include_directories(ssl_test_ctx_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ssl_test_ctx_test PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(ssl_test ssl_test.c)
target_include_directories(ssl_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ssl_test PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(cipherlist_test cipherlist_test.c)
target_include_directories(cipherlist_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cipherlist_test PRIVATE libtestutil ${OPENSSL_LIBRARIES})

add_executable(x509aux x509aux.c)
target_include_directories(x509aux PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(x509aux PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(asynciotest asynciotest.c)
target_include_directories(asynciotest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asynciotest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(bio_callback_test bio_callback_test.c)
target_include_directories(bio_callback_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bio_callback_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(bio_memleak_test bio_memleak_test.c)
target_include_directories(bio_memleak_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bio_memleak_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})


add_executable(bioprinttest bioprinttest.c)
target_include_directories(bioprinttest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bioprinttest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(sslapitest sslapitest.c)
target_include_directories(sslapitest PRIVATE .. ${OPENSSL_INCLUDE_DIR})
target_link_libraries(sslapitest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(ocspapitest ocspapitest.c)
target_include_directories(ocspapitest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ocspapitest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(dtlstest dtlstest.c)
target_include_directories(dtlstest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dtlstest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(sslcorrupttest sslcorrupttest.c)
target_include_directories(sslcorrupttest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(sslcorrupttest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(bio_enc_test bio_enc_test.c)
target_include_directories(bio_enc_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bio_enc_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(pkey_meth_test pkey_meth_test.c)
target_include_directories(pkey_meth_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pkey_meth_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(pkey_meth_kdf_test pkey_meth_kdf_test.c)
target_include_directories(pkey_meth_kdf_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pkey_meth_kdf_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(x509_time_test x509_time_test.c)
target_include_directories(x509_time_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(x509_time_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(recordlentest recordlentest.c)
target_include_directories(recordlentest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(recordlentest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

# Skipping drbgtest because it links with libcrypto.a
#add_executable(drbgtest drbgtest.c)
#target_include_directories(drbgtest PRIVATE .. . ${OPENSSL_INCLUDE_DIR})
#target_link_libraries(drbgtest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

# Skipping drbg_cavs_test because it uses RAND_DRBG, which is removed in 3.0
# add_executable(drbg_cavs_test drbg_cavs_test.c drbg_cavs_data.c)
# target_include_directories(drbg_cavs_test PRIVATE .. . ${OPENSSL_INCLUDE_DIR})
# target_link_libraries(drbg_cavs_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(x509_dup_cert_test x509_dup_cert_test.c)
target_include_directories(x509_dup_cert_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(x509_dup_cert_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(x509_check_cert_pkey_test x509_check_cert_pkey_test.c)
target_include_directories(x509_check_cert_pkey_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(x509_check_cert_pkey_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(pemtest pemtest.c)
target_include_directories(pemtest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pemtest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(ssl_cert_table_internal_test ssl_cert_table_internal_test.c)
target_include_directories(ssl_cert_table_internal_test PRIVATE .. ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ssl_cert_table_internal_test PRIVATE libtestutil ${OPENSSL_LIBRARIES})

add_executable(ciphername_test ciphername_test.c)
target_include_directories(ciphername_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ciphername_test PRIVATE libtestutil ${OPENSSL_LIBRARIES})


add_executable(servername_test servername_test.c)
target_include_directories(servername_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(servername_test PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

# Unless cms is disabled
add_executable(cmsapitest cmsapitest.c)
target_include_directories(cmsapitest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cmsapitest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

# Unless psk is disabled
# Skipping this, as it uses internal libssl stuff, which are not compatible
# across OpenSSL versions
#add_executable(dtls_mtu_test dtls_mtu_test.c)
#target_include_directories(dtls_mtu_test PRIVATE .. ${OPENSSL_INCLUDE_DIR})
#target_link_libraries(dtls_mtu_test PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

# Skipping, because cmake won't link it with libdl, even thought I use
# ${CMAKE_DL_LIBS}
#add_executable(shlibloadtest shlibloadtest.c)
#target_include_directories(shlibloadtest PRIVATE ${OPENSSL_INCLUDE_DIR})

#  IF[{- $disabled{shared} -}]
#    PROGRAMS_NO_INST=cipher_overhead_test
#    SOURCE[cipher_overhead_test]=cipher_overhead_test.c
#    INCLUDE[cipher_overhead_test]=.. ../include
#    DEPEND[cipher_overhead_test]=../libcrypto ../libssl libtestutil.a
#  ENDIF

add_executable(uitest uitest.c)
target_include_directories(uitest PRIVATE .. ${OPENSSL_INCLUDE_DIR})
target_link_libraries(uitest PRIVATE libapps libtestutil ${OPENSSL_LIBRARIES})

add_executable(cipherbytes_test cipherbytes_test.c)
target_include_directories(cipherbytes_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cipherbytes_test PRIVATE libtestutil ${OPENSSL_LIBRARIES})

add_executable(asn1_encode_test asn1_encode_test.c)
target_include_directories(asn1_encode_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asn1_encode_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(asn1_decode_test asn1_decode_test.c)
target_include_directories(asn1_decode_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asn1_decode_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(asn1_string_table_test asn1_string_table_test.c)
target_include_directories(asn1_string_table_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asn1_string_table_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(time_offset_test time_offset_test.c)
target_include_directories(time_offset_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(time_offset_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(conf_include_test conf_include_test.c)
target_include_directories(conf_include_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(conf_include_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

# Skipping the following internal tests, because they require static
# libcrypto or libssl, to access truly internal stuff.
#    PROGRAMS_NO_INST=asn1_internal_test modes_internal_test x509_internal_test \
#                     tls13encryptiontest wpackettest ctype_internal_test \
#                     rdrand_sanitytest
#    IF[{- !$disabled{poly1305} -}]
#      PROGRAMS_NO_INST=poly1305_internal_test
#    ENDIF
#    IF[{- !$disabled{chacha} -}]
#      PROGRAMS_NO_INST=chacha_internal_test
#    ENDIF
#    IF[{- !$disabled{siphash} -}]
#      PROGRAMS_NO_INST=siphash_internal_test
#    ENDIF
#    IF[{- !$disabled{sm2} -}]
#      PROGRAMS_NO_INST=sm2_internal_test
#    ENDIF
#    IF[{- !$disabled{sm4} -}]
#      PROGRAMS_NO_INST=sm4_internal_test
#    ENDIF
#    IF[{- !$disabled{ec} -}]
#      PROGRAMS_NO_INST=ec_internal_test curve448_internal_test
#    ENDIF
#    IF[{- !$disabled{cmac} -}]
#      PROGRAMS_NO_INST=cmactest
#    ENDIF

add_executable(mdc2_internal_test mdc2_internal_test.c)
target_include_directories(mdc2_internal_test PRIVATE .. ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mdc2_internal_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(asn1_time_test asn1_time_test.c)
target_include_directories(asn1_time_test PRIVATE .. ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asn1_time_test PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

# Skipping: tls13secretstest

add_executable(sslbuffertest sslbuffertest.c)
target_include_directories(sslbuffertest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(sslbuffertest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(sysdefaulttest sysdefaulttest.c)
target_include_directories(sysdefaulttest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(sysdefaulttest PRIVATE libtestutil ${OPENSSL_LIBRARIES})

add_executable(errtest errtest.c)
target_include_directories(errtest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(errtest PRIVATE libtestutil ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(gosttest gosttest.c)
target_include_directories(gosttest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(gosttest PRIVATE ssltestlib libtestutil ${OPENSSL_LIBRARIES})

add_executable(ssl_ctx_test ssl_ctx_test.c)
target_include_directories(ssl_ctx_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ssl_ctx_test PRIVATE libtestutil ${OPENSSL_LIBRARIES})
