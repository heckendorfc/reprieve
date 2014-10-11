# - Try to find LibYAMLDOM
# Once done this will define
#
#  LIBYAMLDOM_FOUND - system has LibYAMLDOM
#  LIBYAMLDOM_INCLUDE_DIRS - the LibYAMLDOM include directory
#  LIBYAMLDOM_LIBRARIES - Link these to use LibYAMLDOM
#  LIBYAMLDOM_DEFINITIONS - Compiler switches required for using LibYAMLDOM
#
#  Copyright (c) 2014  <>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (LIBYAMLDOM_LIBRARIES AND LIBYAMLDOM_INCLUDE_DIRS)
  # in cache already
  set(LIBYAMLDOM_FOUND TRUE)
else (LIBYAMLDOM_LIBRARIES AND LIBYAMLDOM_INCLUDE_DIRS)
  find_path(LIBYAMLDOM_INCLUDE_DIR
    NAMES
      yamldom.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )

  find_library(YAMLDOM_LIBRARY
    NAMES
      yamldom
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(LIBYAMLDOM_INCLUDE_DIRS
    ${LIBYAMLDOM_INCLUDE_DIR}
  )
  set(LIBYAMLDOM_LIBRARIES
    ${YAMLDOM_LIBRARY}
)

  if (LIBYAMLDOM_INCLUDE_DIRS AND LIBYAMLDOM_LIBRARIES)
     set(LIBYAMLDOM_FOUND TRUE)
  endif (LIBYAMLDOM_INCLUDE_DIRS AND LIBYAMLDOM_LIBRARIES)

  if (LIBYAMLDOM_FOUND)
    if (NOT LibYAMLDOM_FIND_QUIETLY)
      message(STATUS "Found LibYAMLDOM: ${LIBYAMLDOM_LIBRARIES}")
    endif (NOT LibYAMLDOM_FIND_QUIETLY)
  else (LIBYAMLDOM_FOUND)
    if (LibYAMLDOM_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find LibYAMLDOM")
    endif (LibYAMLDOM_FIND_REQUIRED)
  endif (LIBYAMLDOM_FOUND)

  # show the LIBYAMLDOM_INCLUDE_DIRS and LIBYAMLDOM_LIBRARIES variables only in the advanced view
  mark_as_advanced(LIBYAMLDOM_INCLUDE_DIRS LIBYAMLDOM_LIBRARIES)

endif (LIBYAMLDOM_LIBRARIES AND LIBYAMLDOM_INCLUDE_DIRS)

