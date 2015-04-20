#ifndef _INC_MEMTRACE_H
#define _INC_MEMTRACE_H

#include <stdint.h>

#if __LP64__
#define	IS64BIT	1
#else
#define	IS64BIT	0
#endif

#define	MEMTRACE_SI_VERSION	5

#define	MEMTRACE_SI_FORK	1
#define	MEMTRACE_SI_EXEC	2
#define	MEMTRACE_SI_VERBOSE	4

enum mt_operation {
	MT_DISCONNECT,
	MT_INFO,
	MT_ADD_MAP,
	MT_DEL_MAP,
	MT_ATTACH,
	MT_ATTACH64,
	MT_FORK,
	MT_ABOUT_EXIT,
	MT_EXIT,
	MT_NOFOLLOW,
	MT_MALLOC,
	MT_REALLOC_ENTER,
	MT_REALLOC_FAILED,
	MT_REALLOC,
	MT_FREE,
	MT_MMAP,
	MT_MMAP64,
	MT_MUNMAP,
	MT_MEMALIGN,
	MT_POSIX_MEMALIGN,
	MT_ALIGNED_ALLOC,
	MT_VALLOC,
	MT_PVALLOC,
	MT_SCAN,
	MT_STOP,
	MT_START,
	MT_DETACH,
};

struct mt_msg {
	uint16_t operation;
	uint32_t pid;
	uint32_t tid;
	uint32_t payload_len;
};

struct mt_alloc_payload_64 {
	uint64_t ptr;
	uint64_t size;
	uint64_t data[0];
};

struct mt_alloc_payload_32 {
	uint32_t ptr;
	uint32_t size;
	uint32_t data[0];
};

struct mt_pid_payload {
	uint32_t pid;
};

struct mt_scan_payload {
	uint32_t ptr_size;
	uint64_t mask;
	char data[0];
};

struct memtrace_info {
	uint8_t	version;
	uint8_t	mode;
	uint8_t	do_trace;
	uint8_t stack_depth;
};

struct mt_map_payload {
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	char filename[0];
};

#endif

