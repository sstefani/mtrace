function(target_architecture output_var)

set(archdetect_c_code "
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(_M_ARM)
	#error cmake_ARCH arm
#elif defined(__aarch64__) || defined(_M_ARM64)
	#error cmake_ARCH aarch64
#elif defined(__i386) || defined(__i386__) || defined(_M_IX86)
	#error cmake_ARCH x86
#elif defined(__x86_64) || defined(x__x86_64__) || defined(__amd64) || defined(_M_X64)
	#error cmake_ARCH x86_64
#elif defined(__ia64) || defined(__ia64__) || defined(_M_IA64)
	#error cmake_ARCH ia64
#elif defined(__ppc__) || defined(__ppc) || defined(__powerpc__) || defined(_ARCH_COM) || defined(_ARCH_PWR) || defined(_ARCH_PPC) || defined(_M_MPPC) || defined(_M_PPC)
	#if defined(__ppc64__) || defined(__powerpc64__) || defined(__64BIT__)
		#error cmake_ARCH ppc64
	#else
		#error cmake_ARCH ppc
	#endif
#elif defined(__mips64)
	#error cmake_ARCH mips64
#elif defined(__mips)
	#error cmake_ARCH mips
#endif

#error cmake_ARCH unknown
")

	set(F "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/_test_.c")

	file(WRITE ${F} "${archdetect_c_code}")

	enable_language(C)

	try_run(
		run_result_unused
		compile_result_unused
		"${CMAKE_BINARY_DIR}"
		"${F}"
		COMPILE_OUTPUT_VARIABLE ARCH
		CMAKE_FLAGS CMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
	)
	file(REMOVE "${F}" "${osdetect_c_code}")

	string(REGEX MATCH "cmake_ARCH ([a-zA-Z0-9_]+)" ARCH "${ARCH}")

	string(REPLACE "cmake_ARCH " "" ARCH "${ARCH}")

	if (NOT ARCH)
		set(ARCH unknown)
	endif()

	set(${output_var} "${ARCH}" PARENT_SCOPE)
endfunction()

function(target_os output_var)

set(osdetect_c_code "
#if defined(_WIN32) || defined(_WIN64)
	#error cmake_OS windows
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
	#error cmake_OS linux
#elif defined(__APPLE__) && defined(TARGET_OS_MAC)
	#error cmake_OS osx
#elif defined(__unix__)
	#error cmake_OS unix
#endif

#error cmake_ARCH unknown
")

	set(F "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/_test_.c")

	file(WRITE ${F} "${osdetect_c_code}")

	enable_language(C)

	try_run(
		run_result_unused
		compile_result_unused
		"${CMAKE_BINARY_DIR}"
		"${F}"
		COMPILE_OUTPUT_VARIABLE OS
		CMAKE_FLAGS CMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
	)
	file(REMOVE "${F}" "${osdetect_c_code}")

	string(REGEX MATCH "cmake_OS ([a-zA-Z0-9_]+)" OS "${OS}")

	string(REPLACE "cmake_OS " "" OS "${OS}")

	if (NOT OS)
		set(OS unknown)
	endif()

	set(${output_var} "${OS}" PARENT_SCOPE)
endfunction()

macro(CHECK_INCLUDE_FILES_ERROR INCLUDE_FILES HAVE_FILE)
	CHECK_INCLUDE_FILES("${INCLUDE_FILES}" ${HAVE_FILE})
	IF(NOT ${HAVE_FILE})
		message(FATAL_ERROR "${INCLUDE_FILE} not found")
	ENDIF()
endmacro()

function(find_library_error VAR LIB)
	find_library(${VAR} ${LIB})
	IF (NOT ${VAR})
		message(FATAL_ERROR "lib ${LIB} not found")
	ENDIF()
endfunction()

function(find_and_test_library VAR LIB INCLUDES SYM)
	find_library_error(${VAR} "${LIB}")
	CHECK_INCLUDE_FILES_ERROR("${INCLUDES}" _HAVE_FILE)
	set(CMAKE_REQUIRED_LIBRARIES "${${VAR}}")
	set(HAVE_SYM "_HAVE_SYM_${SYM}")
	check_symbol_exists("${SYM}" "${INCLUDES}" ${HAVE_SYM})
	IF (NOT ${HAVE_SYM})
		message(FATAL_ERROR "symbol ${SYM} not found in library ${LIB}")
	endif()
endfunction()


function(echo_all_cmake_variable_values)
  get_cmake_property(vs VARIABLES)
  foreach(v ${vs})
    message(STATUS "${v}='${${v}}'")
  endforeach(v)
endfunction()

