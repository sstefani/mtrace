Mtrace
------

mtrace is an interactive dynamic memory tracer, debugger and statistical analyses tool for C and C++, which intercepts, records and reports all kinds of dynamic memory allocations.

It supports the developer to get statistics about the memory usage and finding memory leaks in an arbitrate program.  Since mtrace is using breakpoints for tracing the program, there is no need of modification of the source code nor any recompilation.

The mtrace utility intercepts the following library calls:

	void *malloc(size_t size);
	void free(void *ptr);
	void *calloc(size_t nmemb, size_t size);
	void *realloc(void *ptr, size_t size);
	int posix_memalign(void **memptr, size_t alignment, size_t size);
	void *aligned_alloc(size_t alignment, size_t size);
	void *valloc(size_t size);
	void *memalign(size_t alignment, size_t size);
	void *pvalloc(size_t size);
	void cfree(void *ptr);
	void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	int munmap(void *addr, size_t length);
	void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);

	void *operator new(size_t size) throw (std::bad_alloc)
	void *operator new(size_t size, const std::nothrow_t& nt) __THROW
	void *operator new[](size_t size) throw (std::bad_alloc)
	void *operator new[](size_t size, const std::nothrow_t& nt) __THROW
	void operator delete(void* p) __THROW
	void operator delete(void* p, const std::nothrow_t& nt) __THROW
	void operator delete[](void* p) __THROW
	void operator delete[](void* p, const std::nothrow_t& nt) __THROW


For each allocation a backtrace will be recorded.  This backtrace allows to trace and identify the callers of an allocation function.  The depth of this backtrace could be set by the -d option. Identical backtraces will be handled as one caller, since there is no way to distinguish the callers.

Unlike other dynamic memory tracer, mtrace is able to find no longer referenced memory allocation by scanning all writable memory mappings of the program against the pointer values of the allocations.  If a pointer value of an open allocated memory block will not found on any aligned memory addresses, it will be marked and reported as leaked.  The scan can take some time, depending on the size of the writeable memory mappings and the number of open allocations.

The mtrace utility was designed to run in a very constrained environment, like small embedded systems.  This is one of the reasons for a client/server architecture.  The server runs on the target side and the interactive client runs on the host side, the communication is done via TCP.  If server and client running on the same machine then the communication can be done via UNIX Domain Socket.  Both sides can run on different architectures, address sizes and endianness, but for tracing 64 bit programs the client must be compiled as a 64 bit program.  On the host side all binaries (including debug information) must be accessible, there is no need for debug information on the target side.


mtrace offers different kind of working modes.  A non interactive mode, a server mode and a interactive client mode.

Non interactive mode
--------------------
The most common mode is the non interactive mode, which allows to run and/or attach to a process, similar to strace.  mtrace will show all open allocations when the traced program exists or mtrace will be terminated.

Server mode
-----------
For system with memory restrictions or for using in a cross architecture environment, mtrace offers a server mode which moves the memory bookkeeping and address resolution outside to a connected client.  In this case the server must be started on target system where the program is executed.  Then the client has to be started on the remote host system.

Interactive client mode
-----------------------
To get a more detailed information about the dynamic memory consumption mtrace can be started in an interactive mode.  This mode is available for client mode or when attaching to a process.  See the section INTERACTIVE MODE of the manual page mtrace(1) to learn more about the interactive commands in mtrace.


Restrictions
------------
There is currently support for X86 (32 and 64 Bit), PowerPC (32 Bit) and ARM (32 Bit, no Thumb support).  Only Linux is now supported, but there are plans to support different operating systems and CPU's.


Munich, Germany
6. Mai 2015
Stefani Seibold

