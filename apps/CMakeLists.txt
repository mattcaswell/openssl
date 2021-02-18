set(LIBAPPS_SOURCE
  apps.c opt.c s_cb.c s_socket.c app_rand.c bf_prefix.c
  )

set(OPENSSL_SOURCE
  openssl.c
  asn1pars.c ca.c ciphers.c cms.c crl.c crl2p7.c dgst.c
  enc.c errstr.c
  genpkey.c nseq.c passwd.c pkcs7.c pkcs8.c
  pkey.c pkeyparam.c pkeyutl.c prime.c rand.c req.c
  s_client.c s_server.c s_time.c sess_id.c smime.c speed.c spkac.c
  verify.c version.c x509.c rehash.c storeutl.c

  pkcs12.c                      # Unless des disabled
  ec.c ecparam.c                # Unless ec disabled
  ocsp.c                        # Unless ocsp disabled
  srp.c                         # Unless srp disabled
  ts.c                          # Unless ts disabled
  dhparam.c                     # Unless dh disabled
  dsa.c dsaparam.c gendsa.c     # Unless dsa disabled
  engine.c                      # Unless engine disabled
  rsa.c rsautl.c genrsa.c       # Unless rsa disabled ???
  )

add_library(libapps STATIC ${LIBAPPS_SOURCE})
target_compile_definitions(libapps PUBLIC OPENSSL_UNISTD=<unistd.h>)
target_include_directories(libapps
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..
  PRIVATE ${OPENSSL_INCLUDE_DIR})

set(PROGS_SOURCE)
foreach(_E ${OPENSSL_SOURCE})
  list(APPEND PROGS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/${_E})
endforeach()
add_custom_command(
  OUTPUT progs.h
  DEPENDS progs.pl ${OPENSSL_SOURCE}
  COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/progs.pl ${PROGS_SOURCE} > progs.h)

add_executable(openssl progs.h ${OPENSSL_SOURCE})
target_compile_definitions(libapps PUBLIC OPENSSL_NO_HEARTBEATS)
target_include_directories(openssl PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(openssl PRIVATE libapps ${OPENSSL_LIBRARIES})
