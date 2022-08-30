/* liblink.c - Helper library definining the full link_map structure */

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#if __LP64__
typedef __ino64_t ino64_t;
#endif

#if __aarch64__
#define DT_THISPROCNUM DT_AARCH64_NUM
#elif __ppc64__
#define DT_THISPROCNUM DT_PPC64_NUM
#define DL_FIXUP_VALUE_TYPE ElfW(Addr)
#elif __ppc__
#define DT_THISPROCNUM DT_PPC_NUM
#define DL_FIXUP_VALUE_TYPE ElfW(Addr)
#elif __sparc__
#define DT_THISPROCNUM DT_SPARC_NUM
#elif __mips__
#define DT_THISPROCNUM DT_MIPS_NUM
#elif __alpha__
#define DT_THISPROCNUM DT_ALPHA_NUM
#else
#define DT_THISPROCNUM 0
#define DL_FIXUP_VALUE_TYPE ElfW(Addr)
#endif

#if __aarch64__
struct link_map_machine {
  ElfW(Addr) plt;
  void *tlsdesc_table;
  bool bti_fail;
};
#elif __arm__
struct link_map_machine {
  Elf32_Addr plt;
  void *tlsdesc_table;
};
#elif __i386__
struct link_map_machine {
  Elf32_Addr plt;
  Elf32_Addr gotplt;
  void *tlsdesc_table;
};
#elif __mips__
struct link_map_machine {
  ElfW(Addr) plt;
  ElfW(Word) fpabi;
  unsigned int odd_spreg;
  const Elf32_Word *mips_xlat_zero;
};
#elif __riscv
struct link_map_machine {
  ElfW(Addr) plt;
};
#elif __s390x__
struct link_map_machine {
  Elf64_Addr plt;
  const Elf64_Rela *jmprel;
};
#elif __s390__
struct link_map_machine {
  Elf32_Addr plt;           /* Address of .plt + 0x2c */
  const Elf32_Rela *jmprel; /* Address of first JMP_SLOT reloc */
};
#elif __x86_64__
struct link_map_machine {
  Elf64_Addr plt;
  Elf64_Addr gotplt;
  void *tlsdesc_table;
};
#else
struct link_map_machine {};
#endif

struct r_file_id {
  dev_t dev;
  ino64_t ino;
};

typedef long int Lmid_t;

struct libname_list;
struct r_found_version;
struct r_search_path_elem;

/* Forward declaration.  */
struct link_map;

/* Structure to describe a single list of scope elements.  The lookup
   functions get passed an array of pointers to such structures.  */
struct r_scope_elem {
  /* Array of maps for the scope.  */
  struct link_map **r_list;
  /* Number of entries in the scope.  */
  unsigned int r_nlist;
};

/* Structure to record search path and allocation mechanism.  */
struct r_search_path_struct {
  struct r_search_path_elem **dirs;
  int malloced;
};

struct link_map_private {
  /* These first few members are part of the protocol with the debugger.
     This is the same format used in SVR4.  */

  ElfW(Addr) l_addr; /* Difference between the address in the ELF
                        file and the addresses in memory.  */
  char *l_name;      /* Absolute file name object was found in.  */
  ElfW(Dyn) * l_ld;  /* Dynamic section of the shared object.  */
  struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

  /* All following members are internal to the dynamic linker.
     They may change without notice.  */

  /* This is an element which is only ever different from a pointer to
     the very same copy of this type for ld.so when it is used in more
     than one namespace.  */
  struct link_map *l_real;

  /* Number of the namespace this link map belongs to.  */
  Lmid_t l_ns;

  struct libname_list *l_libname;
  /* Indexed pointers to dynamic section.
     [0,DT_NUM) are indexed by the processor-independent tags.
     [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
     [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
     indexed by DT_VERSIONTAGIDX(tagvalue).
     [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
      DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
     DT_EXTRATAGIDX(tagvalue).
     [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
      DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
     indexed by DT_VALTAGIDX(tagvalue) and
     [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
      DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
     are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

  ElfW(Dyn) * l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM +
                     DT_VALNUM + DT_ADDRNUM];
  const ElfW(Phdr) * l_phdr; /* Pointer to program header table in core.  */
  ElfW(Addr) l_entry;        /* Entry point location.  */
  ElfW(Half) l_phnum;        /* Number of program header entries.  */
  ElfW(Half) l_ldnum;        /* Number of dynamic segment entries.  */

  /* Array of DT_NEEDED dependencies and their dependencies, in
     dependency order for symbol lookup (with and without
     duplicates).  There is no entry before the dependencies have
     been loaded.  */
  struct r_scope_elem l_searchlist;

  /* We need a special searchlist to process objects marked with
     DT_SYMBOLIC.  */
  struct r_scope_elem l_symbolic_searchlist;

  /* Dependent object that first caused this object to be loaded.  */
  struct link_map *l_loader;

  /* Array with version names.  */
  struct r_found_version *l_versions;
  unsigned int l_nversions;

  /* Symbol hash table.  */
  Elf_Symndx l_nbuckets;
  Elf32_Word l_gnu_bitmask_idxbits;
  Elf32_Word l_gnu_shift;
  const ElfW(Addr) * l_gnu_bitmask;
  union {
    const Elf32_Word *l_gnu_buckets;
    const Elf_Symndx *l_chain;
  };
  union {
    const Elf32_Word *l_gnu_chain_zero;
    const Elf_Symndx *l_buckets;
  };

  unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.  */
  enum                             /* Where this object came from.  */
  {
    lt_executable, /* The main executable program.  */
    lt_library,    /* Library needed by main executable.  */
    lt_loaded      /* Extra run-time loaded shared object.  */
  } l_type : 2;
  unsigned int l_dt_relr_ref : 1; /* Nonzero if GLIBC_ABI_DT_RELR is
                                     referenced.  */
  unsigned int l_relocated : 1;   /* Nonzero if object's relocations done.  */
  unsigned int l_init_called : 1; /* Nonzero if DT_INIT function called.  */
  unsigned int l_global : 1;      /* Nonzero if object in _dl_global_scope.  */
  unsigned int l_reserved : 2;    /* Reserved for internal use.  */
  unsigned int l_main_map : 1; /* Nonzero for the map of the main program.  */
  unsigned int l_visited : 1;  /* Used internally for map dependency
                                  graph traversal.  */
  unsigned int l_map_used : 1; /* These two bits are used during traversal */
  unsigned int l_map_done : 1; /* of maps in _dl_close_worker. */
  unsigned int l_phdr_allocated : 1; /* Nonzero if the data structure pointed
                                        to by `l_phdr' is allocated.  */
  unsigned int l_soname_added : 1;   /* Nonzero if the SONAME is for sure in
                                        the l_libname list.  */
  unsigned int l_faked : 1;          /* Nonzero if this is a faked descriptor
                                        without associated file.  */
  unsigned int l_need_tls_init : 1;  /* Nonzero if GL(dl_init_static_tls)
                                        should be called on this link map
                                        when relocation finishes.  */
  unsigned int l_auditing : 1; /* Nonzero if the DSO is used in auditing.  */
  unsigned int l_audit_any_plt : 1; /* Nonzero if at least one audit module
                                       is interested in the PLT interception.*/
  unsigned int l_removed : 1;    /* Nozero if the object cannot be used anymore
                                    since it is removed.  */
  unsigned int l_contiguous : 1; /* Nonzero if inter-segment holes are
                                    mprotected or if no holes are present at
                                    all.  */
  unsigned int l_free_initfini : 1; /* Nonzero if l_initfini can be
                                       freed, ie. not allocated with
                                       the dummy malloc in ld.so.  */
  unsigned int l_ld_readonly : 1; /* Nonzero if dynamic section is readonly.  */
  unsigned int l_find_object_processed : 1; /* Zero if _dl_find_object_update
                                               needs to process this
                                               lt_library map.  */

  /* NODELETE status of the map.  Only valid for maps of type
     lt_loaded.  Lazy binding sets l_nodelete_active directly,
     potentially from signal handlers.  Initial loading of an
     DF_1_NODELETE object set l_nodelete_pending.  Relocation may
     set l_nodelete_pending as well.  l_nodelete_pending maps are
     promoted to l_nodelete_active status in the final stages of
     dlopen, prior to calling ELF constructors.  dlclose only
     refuses to unload l_nodelete_active maps, the pending status is
     ignored.  */
  bool l_nodelete_active;
  bool l_nodelete_pending;

#if __i386__ || __x86_64__
  enum {
    lc_property_unknown = 0,   /* Unknown property status.  */
    lc_property_none = 1 << 0, /* No property.  */
    lc_property_valid = 1 << 1 /* Has valid property.  */
  } l_property : 2;

  unsigned int l_x86_feature_1_and;

  unsigned int l_x86_isa_1_needed;

  unsigned int l_1_needed;
#else
  unsigned int l_1_needed;
#endif

  /* Collected information about own RPATH directories.  */
  struct r_search_path_struct l_rpath_dirs;

  /* Collected results of relocation while profiling.  */
  struct reloc_result {
    DL_FIXUP_VALUE_TYPE addr;
    struct link_map *bound;
    unsigned int boundndx;
    uint32_t enterexit;
    unsigned int flags;
    /* CONCURRENCY NOTE: This is used to guard the concurrent initialization
       of the relocation result across multiple threads.  See the more
       detailed notes in elf/dl-runtime.c.  */
    unsigned int init;
  } *l_reloc_result;

  /* Pointer to the version information if available.  */
  ElfW(Versym) * l_versyms;

  /* String specifying the path where this object was found.  */
  const char *l_origin;

  /* Start and finish of memory map for this object.  l_map_start
     need not be the same as l_addr.  */
  ElfW(Addr) l_map_start, l_map_end;
  /* End of the executable part of the mapping.  */
  ElfW(Addr) l_text_end;

  /* Default array for 'l_scope'.  */
  struct r_scope_elem *l_scope_mem[4];
  /* Size of array allocated for 'l_scope'.  */
  size_t l_scope_max;
  /* This is an array defining the lookup scope for this link map.
     There are initially at most three different scope lists.  */
  struct r_scope_elem **l_scope;

  /* A similar array, this time only with the local scope.  This is
     used occasionally.  */
  struct r_scope_elem *l_local_scope[2];

  /* This information is kept to check for sure whether a shared
     object is the same as one already loaded.  */
  struct r_file_id l_file_id;

  /* Collected information about own RUNPATH directories.  */
  struct r_search_path_struct l_runpath_dirs;

  /* List of object in order of the init and fini calls.  */
  struct link_map **l_initfini;

  /* List of the dependencies introduced through symbol binding.  */
  struct link_map_reldeps {
    unsigned int act;
    struct link_map *list[];
  } *l_reldeps;
  unsigned int l_reldepsmax;

  /* Nonzero if the DSO is used.  */
  unsigned int l_used;

  /* Various flag words.  */
  ElfW(Word) l_feature_1;
  ElfW(Word) l_flags_1;
  ElfW(Word) l_flags;

  /* Temporarily used in `dl_close'.  */
  int l_idx;

  struct link_map_machine l_mach;

  struct {
    const ElfW(Sym) * sym;
    int type_class;
    struct link_map *value;
    const ElfW(Sym) * ret;
  } l_lookup_cache;

  /* Thread-local storage related info.  */

  /* Start of the initialization image.  */
  void *l_tls_initimage;
  /* Size of the initialization image.  */
  size_t l_tls_initimage_size;
  /* Size of the TLS block.  */
  size_t l_tls_blocksize;
  /* Alignment requirement of the TLS block.  */
  size_t l_tls_align;
  /* Offset of first byte module alignment.  */
  size_t l_tls_firstbyte_offset;
#ifndef NO_TLS_OFFSET
#define NO_TLS_OFFSET 0
#endif
#ifndef FORCED_DYNAMIC_TLS_OFFSET
#if NO_TLS_OFFSET == 0
#define FORCED_DYNAMIC_TLS_OFFSET -1
#elif NO_TLS_OFFSET == -1
#define FORCED_DYNAMIC_TLS_OFFSET -2
#else
#error "FORCED_DYNAMIC_TLS_OFFSET is not defined"
#endif
#endif
  /* For objects present at startup time: offset in the static TLS block.  */
  ptrdiff_t l_tls_offset;
  /* Index of the module in the dtv array.  */
  size_t l_tls_modid;

  /* Number of thread_local objects constructed by this DSO.  This is
     atomically accessed and modified and is not always protected by the load
     lock.  See also: CONCURRENCY NOTES in cxa_thread_atexit_impl.c.  */
  size_t l_tls_dtor_count;

  /* Information used to change permission after the relocations are
     done.  */
  ElfW(Addr) l_relro_addr;
  size_t l_relro_size;

  unsigned long long int l_serial;
};