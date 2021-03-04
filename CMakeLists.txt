cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(
  openssl-programs
  VERSION 1.1.1
  LANGUAGES C)
set(CMAKE_C_STANDARD 90)

option(ENABLE_ASAN "Enable build with the Address sanitizer" OFF)
option(ENABLE_UBSAN "Enable build with the Undefined Behaviour sanitizer" OFF)

if(CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES "GNU")
  add_compile_options(
    -Wno-deprecated-declarations -Wno-incompatible-pointer-types
    )
  if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
  endif()
  if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-sanitize-recover=all)
  endif()
endif()

if(ENABLE_ASAN OR ENABLE_UBSAN)
  # Sanitizer builds do not tolerate RPATH
  set(CMAKE_SKIP_RPATH TRUE)
endif()

find_package(OpenSSL 3.0 REQUIRED)

if (NOT DEFINED OPENSSL_BUILD_DIR)
  message(FATAL_ERROR
    "You don't appear to build against an OpenSSL 3.0 build directory.  "
    "Please make sure to use "
    "-DCMAKE_MODULE_PATH=${CMAKE_CURRENT_SOURCE_DIR}/util/cmake/Modules")
endif()
find_program(OPENSSL_PROGRAM openssl
  PATHS ${OPENSSL_ROOT_DIR} PATH_SUFFIXES apps bin NO_DEFAULT_PATH)
if(OPENSSL_PROGRAM-NOTFOUND)
  message(FATAL_ERROR "Couldn't find the OpenSSL application, given that OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
endif()
message(STATUS "Found OpenSSL application: ${OPENSSL_PROGRAM}")

add_subdirectory(apps)
add_subdirectory(engines)
add_subdirectory(fuzz)
add_subdirectory(test)

# Testing
#enable_testing()

# Prepare the test working directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test-runs)

# Prepare a config file that ensures we always have the default and legacy
# providers
file(GENERATE OUTPUT test/default-and-legacy.cnf
  CONTENT [===[
openssl_conf = openssl_def

[openssl_def]
providers = providers
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
CipherString = DEFAULT:@SECLEVEL=0

[providers]
default = provider_conf
legacy = provider_conf

[provider_conf]
activate = 1
]===])

# Make a fake shlib_wrap.sh.  It doesn't need to do anything, since we're
# setting up the correct environment variables, here and with the help of
# util/perl/WrapOpenSSL.pm
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/util)
file(GENERATE OUTPUT util/shlib_wrap.sh
  CONTENT [===[#! /bin/sh

exec "$@"
]===])

set(TEST_ENVIRONMENT
  OPENSSL_CMAKE_BUILD=1
  SRCTOP=${CMAKE_CURRENT_SOURCE_DIR}
  BLDTOP=${OPENSSL_ROOT_DIR}
  BIN_D=${CMAKE_CURRENT_BINARY_DIR}/apps
  FUZZ_D=${CMAKE_CURRENT_BINARY_DIR}/fuzz
  TEST_D=${CMAKE_CURRENT_BINARY_DIR}/test
  RESULT_D=${CMAKE_CURRENT_BINARY_DIR}/test-runs
  OPENSSL_CONF=${CMAKE_CURRENT_BINARY_DIR}/test/default-and-legacy.cnf
  OPENSSL_MODULES=${OPENSSL_MODULES_DIR}
  OPENSSL_ENGINES=${CMAKE_CURRENT_BINARY_DIR}/engines
  OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}
  OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
  SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}
  PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/test:${CMAKE_CURRENT_SOURCE_DIR}/util/perl
  )

# Because of the little silliness that all cmake versions don't have the
# file(CHMOD) sub-command, we must instead set the permissions of
# util/shlib_wrap.sh in the test commands.
# It's just as well that we add the test target with add_custom_target(),
# because add_test() doesn't allow multiple commands in this manner.

add_custom_target(test
  COMMAND
    chmod a+x util/shlib_wrap.sh
  COMMAND
    ${CMAKE_COMMAND} -E env ${TEST_ENVIRONMENT}
    prove --merge -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/test/recipes/$(TESTS))
