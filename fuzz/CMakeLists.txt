add_executable(asn1-test asn1.c test-corpus.c)
target_include_directories(asn1-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asn1-test PRIVATE ${OPENSSL_LIBRARIES})

add_executable(asn1parse-test asn1parse.c test-corpus.c)
target_include_directories(asn1parse-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asn1parse-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(bignum-test bignum.c test-corpus.c)
target_include_directories(bignum-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bignum-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(bndiv-test bndiv.c test-corpus.c)
target_include_directories(bndiv-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bndiv-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(client-test client.c test-corpus.c)
target_include_directories(client-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(client-test PRIVATE ${OPENSSL_LIBRARIES})

# Unless cms is disabled
add_executable(cms-test cms.c test-corpus.c)
target_include_directories(cms-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cms-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(conf-test conf.c test-corpus.c)
target_include_directories(conf-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(conf-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(crl-test crl.c test-corpus.c)
target_include_directories(crl-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(crl-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

# Unless ct is disabled
add_executable(ct-test ct.c test-corpus.c)
target_include_directories(ct-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ct-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(server-test server.c test-corpus.c)
target_include_directories(server-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(server-test PRIVATE ${OPENSSL_LIBRARIES})

add_executable(x509-test x509.c test-corpus.c)
target_include_directories(x509-test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(x509-test PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})
