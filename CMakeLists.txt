cmake_minimum_required (VERSION 2.6)
project(reprieve)
enable_language(C)

SET(CMAKE_C_FLAGS_DEBUG "-g -O0")
SET(CMAKE_C_FLAGS_RELEASE "-O3")

option(TRY_X11 "Enable X11 clipboard." ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(OpenSSL REQUIRED)
find_package(LibYAML REQUIRED)
find_package(LibYAMLDOM REQUIRED)

if(TRY_X11)
	find_package(X11)
endif(TRY_X11)

if(X11_FOUND)
	set(EXTRA_LIBS ${X11_LIBRARIES})
	set(EXTRA_INCLUDES ${X11_INCLUDE_DIR})
	set(EXTRA_SRC src/xsel.c)
	add_definitions(-DUSE_X11=1)
endif(X11_FOUND)

include_directories(${OPENSSL_INCLUDE_DIR} ${LIBYAML_INCLUDE_DIRS} ${LIBYAMLDOM_INCLUDE_DIRS} ${EXTRA_INCLUDES})

set(SRC_FILES
src/config.c
src/data.c
src/main.c
src/io/io_common.c
src/io/io_config.c
src/io/io_data.c
src/io/io_setup.c
)

add_executable(reprieve ${SRC_FILES} ${EXTRA_SRC})

target_link_libraries(reprieve ${OPENSSL_LIBRARIES} ${LIBYAML_LIBRARIES} ${LIBYAMLDOM_LIBRARIES} ${EXTRA_LIBS})

install(TARGETS reprieve DESTINATION bin)
