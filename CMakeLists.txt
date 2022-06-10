cmake_minimum_required(VERSION 3.5)
set(MT "mtrace-ng")
project(${MT} C)

set(MT_VERSION_STRING "0.8.2")

option(DISABLE_CLIENT "whether to disable client support" OFF)

set(default_build_type "Release")
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose type of build" FORCE)
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
		"Debug" "Release" "LTO")
endif()

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)

include(${CMAKE_SOURCE_DIR}/Utilities.cmake)

SET(C_SRCS
 breakpoint.c
 common.c
 debug.c
 dict.c
 dwarf.c
 event.c
 library.c
 main.c
 mtelf.c
 options.c
 rbtree.c
 report.c
 server.c
 task.c
 trace.c
)

include_directories(
 "${PROJECT_BINARY_DIR}"
 "${PROJECT_SOURCE_DIR}"
 "${PROJECT_SOURCE_DIR}/sysdeps"
)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -D__FORITFY_SOURCE=2 -rdynamic -DDEBUG")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined")

set(CMAKE_C_FLAGS_LTO "${CMAKE_C_FLAGS_RELEASE} -flto")
set(CMAKE_EXE_LINKER_FLAGS_LTO "${CMAKE_LINKER_FLAGS_RELEASE} -flto")

add_compile_options(-Wall -Wextra)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 7)
		add_compile_option(-Wno-implicit-fallthrough)
endif()

if (NOT DISABLE_CLIENT)
	SET(C_SRCS
	 ${C_SRCS}
	 client/binfile.c
	 client/client.c
	 client/dump.c
	 client/job.c
	 client/process.c
	 client/readline.c
	)

	include_directories(
	 "${PROJECT_SOURCE_DIR}/client"
	)
endif()

target_architecture(TARGET_ARCH)
if (TARGET_ARCH)
	message(STATUS "target architecture is ${TARGET_ARCH}")
else()
	message(FATAL_ERROR "unknown target architecture")
endif()

if (TARGET_ARCH MATCHES "x86|x86_64")
	set(MT_CPU "x86")
elseif (TARGET_ARCH MATCHES "arm")
	set(MT_CPU "arm")
elseif (TARGET_ARCH MATCHES "powerpc")
	set(MT_CPU "ppc")
else()
	message(FATAL_ERROR "unsuported target architecture: ${TARGET_ARCH}")
endif()

target_os(TARGET_OS)
if (TARGET_OS)
	message(STATUS "target OS is ${TARGET_OS}")
else()
	message(FATAL_ERROR "unknown target OS: ${TARGET_OS}")
endif()

if (TARGET_OS STREQUAL "linux")
	set(MT_OS "linux-gnu")
else()
	message(FATAL_ERROR "unsuported target os ${TARGET_OS}")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIB_ELF REQUIRED libelf)

find_and_test_library(LIB_PTHREAD pthread "pthread.h" "pthread_create")

set(CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
find_and_test_library(LIB_DL dl "dlfcn.h" dladdr)
unset(CMAKE_REQUIRED_DEFINITIONS)

find_and_test_library(LIB_RT rt "time.h" "clock_gettime")

if (NOT DISABLE_CLIENT)
	set(CURSES_NEED_NCURSES TRUE)
	find_package(Curses REQUIRED)

	find_and_test_library(LIB_READLINE readline "stdio.h;readline/readline.h" "rl_callback_read_char")

	set(CMAKE_REQUIRED_DEFINITIONS "-DPACKAGE_VERSION=${MT_VERSION_STRING}")
	find_and_test_library(LIB_BFD bfd "bfd.h" "bfd_openr")
	unset(CMAKE_REQUIRED_DEFINITIONS)

	CHECK_INCLUDE_FILES_ERROR("termcap.h" HAVE_TERMCAP_H)

	CHECK_INCLUDE_FILES_ERROR("libiberty/demangle.h" HAVE_DEMANGLE_H)
endif()

check_function_exists(process_vm_readv HAVE_PROCESS_VM_READV)

configure_file(
 "${PROJECT_SOURCE_DIR}/config.h.in"
 "${PROJECT_BINARY_DIR}/config.h"
)

include(${CMAKE_SOURCE_DIR}/sysdeps/${MT_OS}/sysdeps.cmake)

if (LIB_ELF_INCLUDE_DIRS)
	include_directories("${LIB_ELF_INCLUDE_DIRS}")
endif()

add_executable(${MT} ${C_SRCS})
target_link_libraries(${MT} ${LIB_ELF_LIBRARIES} ${LIB_PTHREAD} ${LIB_DL} ${LIB_RT} ${LIB_READLINE} ${LIB_BFD})
target_compile_options(${MT} PUBLIC ${LIB_ELF_CFLAGS_OTHER})

install(TARGETS ${PROJECT_NAME} DESTINATION bin/)
install(FILES ${MT}.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 COMPONENT doc)
install(FILES ${MT}.conf.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5 COMPONENT doc)

#echo_all_cmake_variable_values()

