# This is free and unencumbered software released into the public domain.
# For more information, please refer to <http://unlicense.org/>
# Original author: Richard Levitte <richard@levitte.org>
#[=======================================================================[.rst:
FindOpenSSL
-----------

Find the OpenSSL encryption library, allowing even an OpenSSL build tree.
This piggy-backs on the standard FindOpenSSL, and will additionally do the
following:

If there is no ``OPENSSL_ROOT_DIR`` (because the user chose to use
``CMAKE_PREFIX_PATH``), it gets created, using ``OPENSSL_INCLUDE_DIR``
as starting point.

If the file ``configdata.pm`` is found in the directory
``${OPENSSL_ROOT_DIR}``, the following variables are adjusted or added:

``OPENSSL_INCLUDE_DIR``
  Is set to list two directories, the OpenSSL build directory and the
  OpenSSL source directory, allowing for out-of-source builds.
``OPENSSL_BUILD_DIR``
  Is set to the OpenSSL build directory.
``OPENSSL_SOURCE_DIR``
  Is set to the OpenSSL source directory.
``OPENSSL_ENGINES_DIR``
  Is set to the directory where engine modules are found
``OPENSSL_MODULES_DIR``
  Is set to the directory where OpenSSL modules, such as providers, are
  found

To use this module, simply add the following to your cmake command line:

``-DCMAKE_MODULE_PATH=/path/to/this/module``

(you will have to modify ``/path/to/this/module`` to the real path)

With that, the usual ``find_package(OpenSSL)`` will use this module
automatically.

#]=======================================================================]

set(_levitte_save_CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH})
set(CMAKE_MODULE_PATH "")

include(FindOpenSSL)

if (NOT DEFINED OPENSSL_ROOT_DIR)
  # OPENSSL_INCLUDE_DIR is the most reliable directory to go from
  get_filename_component(OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR} DIRECTORY)
endif()
if (EXISTS ${OPENSSL_ROOT_DIR}/configdata.pm)
  # OpenSSL was found in a build directory.  It's known that the package
  # finder may generate an incomplete OPENSSL_INCLUDE_DIR in that case.

  # Build and source directories
  file(STRINGS ${OPENSSL_ROOT_DIR}/configdata.pm _D
    REGEX "\"(source|build)dir\" => \"")
  foreach(_E ${_D})
    string(REGEX REPLACE "^.*\"(source|build)dir\" => \"([^\"]*)\".*\$" "\\1=\\2"
      _E ${_E})
    string(REPLACE "=" ";" _E ${_E})
    list(GET _E 0 _VAR)
    list(GET _E 1 _VAL)
    string(TOUPPER ${_VAR} _VAR)
    set(OPENSSL_${_VAR}_DIR ${_VAL})
  endforeach()
  get_filename_component(OPENSSL_BUILD_DIR ${OPENSSL_BUILD_DIR}
    REALPATH BASE_DIR ${OPENSSL_ROOT_DIR})
  get_filename_component(OPENSSL_SOURCE_DIR ${OPENSSL_SOURCE_DIR}
    REALPATH BASE_DIR ${OPENSSL_BUILD_DIR})
  message("-- Found OpenSSL source directory: ${OPENSSL_SOURCE_DIR}")
  message("-- Found OpenSSL build directory: ${OPENSSL_BUILD_DIR}")
  # Amend include directories
  list(APPEND OPENSSL_INCLUDE_DIR ${OPENSSL_SOURCE_DIR}/include)
  # The standard ENGINEs directory
  set(OPENSSL_ENGINES_DIR ${OPENSSL_BUILD_DIR}/engines)
  # The standard modules (providers) directory
  set(OPENSSL_MODULES_DIR ${OPENSSL_BUILD_DIR}/providers)
else()
  # The standard ENGINEs directory
  get_filename_component(_D ${OPENSSL_CRYPTO_LIBRARY} DIRECTORY)
  set(OPENSSL_ENGINES_DIR ${_D}/engines-${OPENSSL_VERSION_MAJOR}.${OPENSSL_VERSION_MINOR})
  # The standard modules (providers) directory
  set(OPENSSL_MODULES_DIR ${_D}/ossl-modules)
endif()

set(CMAKE_MODULE_PATH ${_levitte_save_CMAKE_MODULE_PATH})
