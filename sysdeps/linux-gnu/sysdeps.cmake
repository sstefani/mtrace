list(APPEND C_SRCS
 sysdeps/${MT_OS}/ioevent.c
 sysdeps/${MT_OS}/os.c
 sysdeps/${MT_OS}/proc.c
 sysdeps/${MT_OS}/socket.c
 sysdeps/${MT_OS}/thread.c
 sysdeps/${MT_OS}/trace.c
)

include_directories("${PROJECT_SOURCE_DIR}/sysdeps/${MT_OS}")
include_directories("${PROJECT_SOURCE_DIR}/sysdeps/${MT_OS}/${MT_CPU}")

include(${CMAKE_SOURCE_DIR}/sysdeps/${MT_OS}/${MT_CPU}/cpu.cmake)

