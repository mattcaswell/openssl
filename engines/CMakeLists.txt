# NOTE: cmake and OpenSSL have different ideas on the suffix of dynamically
# loadable modules on MacOS X.  OpenSSL assumes that the suffix is '.dylib',
# while cmake produces files that end with '.so' by default.  We tailor that
# here by explicitly setting the MODULE suffix to be the same as for shared
# libraries.

add_library(afalgeng MODULE e_afalg.c)
set_target_properties(afalgeng PROPERTIES
  PREFIX "" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
target_include_directories(afalgeng PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(afalgeng PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_library(dasync MODULE e_dasync.c)
set_target_properties(dasync PROPERTIES
  PREFIX "" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
target_include_directories(dasync PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dasync PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_library(ossltest MODULE e_ossltest.c)
set_target_properties(ossltest PROPERTIES
  PREFIX "" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
target_include_directories(ossltest PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ossltest PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

