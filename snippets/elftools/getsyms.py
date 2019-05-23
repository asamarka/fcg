import sys
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import *
from elftools.elf.descriptions import describe_sh_flags
from elftools.elf.constants import *
from elftools.elf.sections import SymbolTableSection
import archinfo


def process_symbol_section(sec, all_syms):
    #print "Number of symbols in section %d" % (sec.num_symbols())

    for sym in sec.iter_symbols():
        info = sym['st_info']

        # Filter non-function and undefined symbols
        if not info['type'] == 'STT_FUNC':
            continue
        if sym['st_shndx'] == 'SHN_UNDEF': # or sym['st_shndx'] <= 0:
            #print "Function symbol not in any section " + sym.name
            continue
        all_syms.append(sym)


def process_elf_file(filename):

    try:
        f = open(filename, 'rb')
        elffile = ELFFile(f)
    except ELFError as e:
        sys.exit("Error parsing ELF file: " + str(e))
    except IOError as e:
        sys.exit("Error opening file: " + str(e))

    """
    arch = elffile.get_machine_arch()

    if arch == "x64":
        a = archinfo.ArchAMD64()
    elif arch == "x86":
        a = archinfo.ArchX86()
    else:
        print "ELF architecture '%s' currently not supported" % (arch)
        sys.exit(1)
    """

    all_syms = [ ]
    secnum = 0
    #print "NUM OF SECTIONS: %d" % (elffile.num_sections())
    for s in elffile.iter_sections():
        if isinstance(s, SymbolTableSection):
            print "SECTION: %d %s %s" % (secnum, s.name, s['sh_size'])
            process_symbol_section(s, all_syms)
        secnum = secnum + 1

    sym_size = [ 0 ] * (elffile.num_sections() + 1)

    print "SEC\tBIND\t\tSIZE\tVALUE\t"
    for sym in all_syms:
        info = sym['st_info']

        print "%s\t%s\t%s\t%x\t%s" % (sym['st_shndx'], info['bind'], sym['st_size'], int(sym['st_value']), sym.name)
        sym_size[sym['st_shndx']] += sym['st_size']

        """
        if t == 'SHT_SYMTAB':
            process_symbol_section(s, all_syms)
        elif t == 'SHT_NULL':
            continue
        elif t == 'SHT_NOTE':
            continue
        elif t == 'SHT_NOBITS':
            continue
        elif t == 'SHT_PROGBITS':
            continue
        elif t == 'SHT_STRTAB':
            continue
        else:
            print "SECTION: %s %s" % (s.name, s['sh_type'])
            print "Don't know how to handle this section, change me!"
            sys.exit(1)
        """

    for i in range(0, elffile.num_sections()):
            if sym_size[i] > 0:
                print "total: %s %d" % (elffile.get_section(i).name, sym_size[i])

def usage(name):
    print "Usage: %s <elf_file>" % (name)


def main():
    if len(sys.argv) < 2:
        print "Too few arguments"
        usage(sys.argv[0])
        exit(1)

    process_elf_file(sys.argv[1])


if __name__ == "__main__":
    main()
