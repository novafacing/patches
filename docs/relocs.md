# Implementing Relocs

Relocs are implemented by using the *real* glibc `_dl_runtime_resolve` function.

* _dl_runtime_resolve(struct link_map *l, ElfW(Word) reloc_arg)
  * _dl_fixup(struct link_map *l, ElfW(Word) reloc_arg)
    * _dl_lookup_symbol_x(char *name, link_map *l, ElfW(Sym) sym, r_scope_elem **scope, version, ELF_RTYPE_CLASS_PLT, flags, NULL)
    * elf_machine_plt_value(link_map *l, ElfW(Rel) reloc, void *value)
    * elf_ifunc_invoke(ElfW(Addr) addr)
    * _dl_audit_symbind(link_map *l, reloc_result *reloc_result, ElfW(Sym) sym, void *value, result)
    * elf_machine_fixup_plt(link_map *l, lookup_t result, ElfW(Sym) *refsym, ElfW(Sym) *sym, ElfW(Rel) *reloc, ElfW(Addr) *reloc_addr, ElfW(Addr) value)

On entry to _dl_runtime_resolve for strdup:

```
pwndbg> stack 2
00:0000│ rsp 0x7fffffffd2f8 —▸ 0x7ffff7ffe190 —▸ 0x555555554000 ◂— 0x10102464c457f
01:0008│     0x7fffffffd300 ◂— 0x3
```
Top of stack is (struct link_map *)
Next item is reloc_arg 0x3 which is the offset in the .rela.plt section of the entry
for strdup.

On entry to _dl_resolve, the symtab is:

```
 p *(Elf64_Sym*)((*(struct link_map *)0x7ffff7ffe190).l_info[6])
$8 = {
  st_name = 6,
  st_info = 0 '\000',
  st_other = 0 '\000',
  st_shndx = 0,
  st_value = 93824992232192,
  st_size = 11
}
```

The first relocation is:


```
p *(Elf64_Rela*)((*(struct link_map *)0x7ffff7ffe190).l_info[23])
$9 = {
  r_offset = 23,
  r_info = 93824992232920,
  r_addend = 2
}
```

While the relocation for strdup is:

```
p *(Elf64_Rela*)(((*(struct link_map *)0x7ffff7ffe190).l_info[23]) + 3)
$22 = {
  r_offset = 20,
  r_info = 7,
  r_addend = 6
}
```

Add types to binaryninja with copy paste ig
