mtrace is an interactive dynamic memory tracer/debugger for C and C++, which intercepts and reports all kinds of dynamic memory allocations.

It supports the developer to get statistics about the memory usage and finding memory leaks in an arbitrate application. There is no need of modification of the source code nor any recompilation.

Unlike other dynamic memory tracer, mtrace is able to find no longer referenced memory allocation by scanning all writable memory mappings of the program against the addresses of the allocation. If the memory address will be not found during a scan there is a high change for a missing reference and therefore for a memory leak.

The mtrace utility was designed to run in a very constrained environment, like small embedded systems. This is one of the reasons for a client/server architecture. The server runs on the target side and the interactive client runs on the host side, the communication is done via TCP. If server and client are on the same machine then the communication can be done via UNIX Domain Socket. Both sides can run on different architectures, address sizes and endianness, but for tracing 64 bit programs the client must be compiled as a 64 bit program. On the host side all binaries (including debug information) must be accessible, there is no need for debug information on the target side.

The mtrace utility intercepts the following GLIBC calls:

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

There is currently support for X86 (32 and 64 Bit), PowerPC (32 Bit) and ARM (32 Bit). Only Linux is now supported, but there are plans to support different operating systems and CPU's.

Stay tuned...

