#! /usr/bin/env python

__author__ = '@theqlabs'

#   Currently a dumb ELF parser (.o, .so and .ko or LKM)
#   Elf_Ehdr, Elf_Phdr and Elf_Shdr all defined by methods
#
# References:
#   http://www.x86-64.org/documentation/abi.pdf
#   http://fluxius.handgrep.se/2011/10/20/the-art-of-elf-analysises-and-exploitations/
#   http://en.wikipedia.org/wiki/X86_calling_conventions

# Inspired by: http://fluxius.handgrep.se/2011/10/20/the-art-of-elf-analysises-and-exploitations/

# TODO - Implement "setters" where I can re-write any piece of the ELF file

import sys
import binascii

ELFMAGIC = 0x7f454c46

"""
                                    ELF Header
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	    /* Magic number and other info */
  Elf64_Half	e_type;			        /* Object file type */
  Elf64_Half	e_machine;		        /* Architecture */
  Elf64_Word	e_version;		        /* Object file version */
  Elf64_Addr	e_entry;		        /* Entry point virtual address */
  Elf64_Off	    e_phoff;		        /* Program header table file offset */
  Elf64_Off	    e_shoff;		        /* Section header table file offset */
  Elf64_Word	e_flags;		        /* Processor-specific flags */
  Elf64_Half	e_ehsize;		        /* ELF header size in bytes */
  Elf64_Half	e_phentsize;		    /* Program header table entry size */
  Elf64_Half	e_phnum;		        /* Program header table entry count */
  Elf64_Half	e_shentsize;		    /* Section header table entry size */
  Elf64_Half	e_shnum;		        /* Section header table entry count */
  Elf64_Half	e_shstrndx;		        /* Section header string table index */
} Elf64_Ehdr;
"""

class Elf_Ehdr(object):

    def __init__(self):
        self.inFile = sys.argv[1]

        with open(self.inFile, mode='rb') as file:
            self.binaryFile = file.read()

        self.elfmag = binascii.hexlify(self.binaryFile[0:4])
        self.ei_class = binascii.hexlify(self.binaryFile[4:5])
        self.ei_data = binascii.hexlify(self.binaryFile[5:6])
        self.ei_version = binascii.hexlify(self.binaryFile[6:7])
        self.ei_osabi = binascii.hexlify(self.binaryFile[7:8])
        self.ei_abiversion = binascii.hexlify(self.binaryFile[8:9])
        self.ei_pad = binascii.hexlify(self.binaryFile[9:16])
        self.e_type_in = binascii.hexlify(self.binaryFile[16:18])
        self.e_machine_in = binascii.hexlify(self.binaryFile[18:19])
        self.e_machine_unused_byte = binascii.hexlify(self.binaryFile[19:20])
        self.e_version_in = binascii.hexlify(self.binaryFile[20:24])
        self.e_entry_in = binascii.hexlify(self.binaryFile[24:32])
        self.e_phoff_in = binascii.hexlify(self.binaryFile[32:40])
        self.e_shoff_in = binascii.hexlify(self.binaryFile[40:48])
        self.e_flags_in = binascii.hexlify(self.binaryFile[48:52])
        self.e_ehsize_in = binascii.hexlify(self.binaryFile[52:54])
        self.e_phentsize_in = binascii.hexlify(self.binaryFile[54:56])
        self.e_phnum_in = binascii.hexlify(self.binaryFile[56:58])
        self.e_shentsize_in = binascii.hexlify(self.binaryFile[58:60])
        self.e_shnum_in = binascii.hexlify(self.binaryFile[60:62])
        self.e_shstrndx_in = binascii.hexlify(self.binaryFile[62:64])

        self.e_ident_out = ""                       # |
        self.e_type_out = ""                        # |
        self.e_machine_out = ""                     # |
        self.e_version_out = ""                     # |
        self.e_entry_out = ""                       # |
        self.e_phoff_out = ""                       # |
        self.e_shoff_out = ""                       # | ---- Human Readable Output from ELF Header
        self.e_flags_out = ""                       # |         These return when you call any get_XXX method
        self.e_ehsize_out = ""                      # |
        self.e_phentsize_out = ""                   # |
        self.e_phnum_out = ""                       # |
        self.e_shentsize_out = ""                   # |
        self.e_shnum_out = ""                       # |
        self.e_shstrndx_out = ""                    # |

    def get_eident(self):
        """
        Magic Number and other info
            We parse e_ident which is part of Elf32_Ehdr and Elf64_Ehdr

            Bytes[0:16]
            ei_* = Raw Bytes from Binary File
            e_ident_out = Bytes Decoded by Header File
        :return:
        """

        # TODO - Not sure lists are smart here, struct seems smarter.
        # TODO - Maybe put each byte (self.binaryFile[n]) into an index-able data structure

        # Magic Number
        if int(self.elfmag, 16) != ELFMAGIC:
            print "This is not an ELF, Peace!"
            sys.exit(1)
        else:
            self.e_ident_out = "ELF, "

        # Class
        if int(self.ei_class, 16) == 0x00:
            self.e_ident_out += "Invalid Class, "
        elif int(self.ei_class, 16) == 0x01:
            self.e_ident_out += "32-bit, "
        elif int(self.ei_class, 16) == 0x02:
            self.e_ident_out += "64-bit, "

        # Data Encoding
        if int(self.ei_data, 16) == 0x00:
            self.e_ident_out += "Invalid Data Encoding, "
        elif int(self.ei_data, 16) == 0x01:
            self.e_ident_out += "Little Endian, "
        elif int(self.ei_data, 16) == 0x02:
            self.e_ident_out += "Big Endian, "

        # Version
        if int(self.ei_version, 16) == 0x01:
            self.e_ident_out += "Current Version, "
        else:
            self.e_ident_out += "Invalid ELF version, "

        # TODO - Read: http://stackoverflow.com/questions/594442/choosing-between-different-switch-case-replacements-in-python-dictionary-or-if
        # OS ABI Identification:
        if int(self.ei_osabi, 16) == 0x00:
            self.e_ident_out += "UNIX System V ABI, "
        elif int(self.ei_osabi, 16) == 0x01:
            self.e_ident_out += "HP_UX, "
        elif int(self.ei_osabi, 16) == 0x02:
            self.e_ident_out += "NetBSD, "
        elif int(self.ei_osabi, 16) == 0x03:
            self.e_ident_out += "(GNU/Linux), "
        elif int(self.ei_osabi, 16) == 0x06:
            self.e_ident_out += "Sun Solaris, "
        elif int(self.ei_osabi, 16) == 0x07:
            self.e_ident_out += "IBM AIX, "
        elif int(self.ei_osabi, 16) == 0x08:
            self.e_ident_out += "SGI Irix, "
        elif int(self.ei_osabi, 16) == 0x09:
            self.e_ident_out += "FreeBSD, "
        elif int(self.ei_osabi, 16) == 0x10:
            self.e_ident_out += "Compaq TRU64 UNIX, "
        elif int(self.ei_osabi, 16) == 0x11:
            self.e_ident_out += "Novell Modesto, "
        elif int(self.ei_osabi, 16) == 0x12:
            self.e_ident_out += "OpenBSD, "
        elif int(self.ei_osabi, 16) == 0x40:
            self.e_ident_out += "ARM EABI, "
        elif int(self.ei_osabi, 16) == 0x61:
            self.e_ident_out += "ARM, "
        elif int(self.ei_osabi, 16) == 0xFF:
            self.e_ident_out += "Standalone (embedded) application, "

        # ABI Version
        if int(self.ei_abiversion, 16) != 0x00:
            self.e_ident_out += "Version: " + self.ei_abiversion

        # Padding Bytes
        if int(self.ei_pad, 16) != 0x00:
            self.e_ident_out += "Padding Bytes: " + self.ei_pad

        return self.e_ident_out

    def get_etype(self):
        """
        Object File Type
            Parsed e_type from Elf32_Ehdr and Elf64_Ehdr

            Bytes[16:18]
            e_type_in = Raw Bytes from Binary File
            e_type_out = Decoded from Header File
        :return:
        """

        if int(self.e_type_in, 16) == 0x0000:
            self.e_type_out += "No File Type, "
        elif int(self.e_type_in, 16) == 0x0100:
            self.e_type_out += "Relocatable File, "
        elif int(self.e_type_in, 16) == 0x0200:
            self.e_type_out += "Executable File, "
        elif int(self.e_type_in, 16) == 0x0300:
            self.e_type_out += "Shared Object File, "
        elif int(self.e_type_in, 16) == 0x0400:
            self.e_type_out += "Core File, "
        elif int(self.e_type_in, 16) == 0x0500:
            self.e_type_out += "Number of defined types, "
        elif int(self.e_type_in, 16) == 0xfe00:
            self.e_type_out += "OS-specific range start, "
        elif int(self.e_type_in, 16) == 0xfeff:
            self.e_type_out += "OS-specific range end, "
        elif int(self.e_type_in, 16) == 0xff00:
            self.e_type_out += "Processor-specific range start, "
        elif int(self.e_type_in, 16) == 0xffff:
            self.e_type_out += "Processor-specific range end, "

        return self.e_type_out

    def get_emachine(self):
        """
        Architecture
            Parsed e_machine from Elf32_Ehdr or Elf64_Ehdr

        Bytes[18:20]
        e_machine_in = Raw Bytes from Binary File
        e_machine_out = Decoded from Header File
        :return:
        """

        # TODO - Add the rest of the e_machine types when I am feeling bored
        # TODO - I should really fix this unused_byte non-sense, conversion issues

        if int(self.e_machine_in, 16) == 00:
            self.e_machine_out += "No machine, "
        elif int(self.e_machine_in, 16) == 03:
            self.e_machine_out += "Intel 80386, "
        elif int(self.e_machine_in, 16) == 07:
            self.e_machine_out += "Intel 80860, "
        elif int(self.e_machine_in, 16) == 20:
            self.e_machine_out += "PowerPC, "
        elif int(self.e_machine_in, 16) == 21:
            self.e_machine_out += "PowerPC 64-bit, "
        elif int(self.e_machine_in, 16) == 40:
            self.e_machine_out += "ARM \n"
        elif int(self.e_machine_in, 16) == 62:
            self.e_machine_out += "x86-64 Architecture, "
        else:
            print "I was lazy and didn't implement your code: " + self.e_machine_in

        return self.e_machine_out

    def get_eversion(self):
        """
        Object file version

        Bytes[20:24]
        e_version_in = Raw Bytes from Binary Files
        e_version_out = Decoded from Header File
        :return:
        """

        # TODO - WTF diff between e_ident version and e_version? Check readelf output
        if int(self.e_version_in, 16) == 0x01000000:
            self.e_version_out += "Version 1, "
        else:
            self.e_version_out += "Version " + self.e_version_in

        return self.e_version_out

    def get_eentry(self):
        """
        Entry point virtual address
            If entry point is 0x00 then program is not linked.

        Bytes[24:32]
        e_entry_in = Raw Bytes from Binary File
        e_entry_out = Decoded from Header File
        :return:
        """

        if binascii.hexlify(self.binaryFile[24]) == 0x00:
            print "No entry point, is your program linked?"
        else:
            self.e_entry_out += "\nEntry Point (Virtual Addr): 0x" + self.e_entry_in + "\n"

        # TODO - Remember to re-order based on LSB or MSB, check value of ei_data
        return self.e_entry_out

    def get_ephoff(self):
        """
        Program header table file offset

        Bytes[32:40]
        e_phoff_in = Raw Bytes from Binary File
        e_phoff_out = Returns decimal value of number of bytes Program Header is offset into file
        :return:
        """

        e_phoff_local = ""

        for n in range(32, 40):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_phoff_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        # converts from str to int, gets dec value then back to str for output
        self.e_phoff_out = int(e_phoff_local, 16)
        self.e_phoff_out = str(self.e_phoff_out)

        return "Start of Program Headers: " + self.e_phoff_out + " (bytes into file)\n"

    def get_eshoff(self):
        """
        Section header table file offset
        :return:
        """

        self.e_shoff_out = self.e_shoff_in

        # TODO - convert to decimal
        return "Start of Section Headers: " + self.e_shoff_out + " (bytes into file)\n"

    def get_eflags(self):
        """
        Processor-specific flags
        :return:
        """

        e_flags_local = ""

        for n in range(48, 52):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_flags_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        if e_flags_local == "":
            e_flags_local = "0x00"
            self.e_flags_out = e_flags_local
        else:
            # TODO - How do I decode Processor flags? Are they defined in elf.h?
            self.e_flags_out = int(e_flags_local, 16)
            self.e_flags_out = str(self.e_flags_out)

        return "Flags: " + self.e_flags_out + "\n"

    def get_eehsize(self):
        """
        ELF Header size in bytes
        :return:
        """

        e_ehsize_local = ""

        for n in range(52, 54):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_ehsize_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        self.e_ehsize_out = int(e_ehsize_local, 16)
        self.e_ehsize_out = str(self.e_ehsize_out)

        return "Size of this header: " + self.e_ehsize_out + " (bytes) \n"

    def get_ephentsize(self):
        """
        Program header table entry size
        :return:
        """

        e_phentsize_local = ""

        for n in range(54, 56):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_phentsize_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        self.e_phentsize_out = int(e_phentsize_local, 16)
        self.e_phentsize_out = str(self.e_phentsize_out)

        return "Size of program headers: " + self.e_phentsize_out + " (bytes) \n"

    def get_ephnum(self):
        """
        Program header table entry count
        :return:
        """

        e_phnum_local = ""

        for n in range(56, 58):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_phnum_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        self.e_phnum_out = int(e_phnum_local, 16)
        self.e_phnum_out = str(self.e_phnum_out)

        return "Number of Program Headers: " + self.e_phnum_out + "\n"

    def get_eshentsize(self):
        """
        Section header table entry size
        :return:
        """

        e_shentsize_local = ""

        for n in range(58, 60):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_shentsize_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        self.e_shentsize_out = int(e_shentsize_local, 16)
        self.e_shentsize_out = str(self.e_shentsize_out)

        return "Size of Section Headers: " + self.e_shentsize_out + " (bytes) \n"

    def get_eshnum(self):
        """
        Section header table entry count
        :return:
        """

        e_shnum_local = ""

        for n in range(60, 62):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_shnum_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        self.e_shnum_out = int(e_shnum_local, 16)
        self.e_shnum_out = str(self.e_shnum_out)

        return "Number of Section Headers: " + self.e_shnum_out + "\n"

    def get_eshstrndx(self):
        """
        Section header string table index
        :return:
        """

        e_shstrndx_local = ""

        for n in range(62, 64):
            if int(binascii.hexlify(self.binaryFile[n]), 16) != 00:
                e_shstrndx_local += binascii.hexlify(self.binaryFile[n])
            else:
                pass

        self.e_shstrndx_out = int(e_shstrndx_local, 16)
        self.e_shstrndx_out = str(self.e_shstrndx_out)

        return "Section header string table index: " + self.e_shstrndx_out + "\n"

    def get_all_ehdr(self):
        """
        Prints all fields of EHDR
        :return:
        """
        # TODO - Populate dictionary where key=struct_field and value is byte value

        print self.get_eident() + self.get_etype() + self.get_emachine() + self.get_eversion() \
            + self.get_eentry() + self.get_ephoff() + self.get_eshoff() + self.get_eflags() \
            + self.get_eehsize() + self.get_ephentsize() + self.get_ephnum() + self.get_eshentsize() \
            + self.get_eshnum() + self.get_eshstrndx()

"""
                                    Section Header
typedef struct
{
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	    sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;	/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf64_Shdr;
"""

class Elf_Shdr(object):

    def __init__(self):
        self.inFile = sys.argv[1]

        with open(self.inFile, mode='rb') as file:              # read binary, = rb
            self.binaryFile = file.read()                       # binary object file

    def get_shname(self):
        pass

    def get_shtype(self):
        pass

    def get_shflags(self):
        pass

    def get_shaddr(self):
        pass

    def get_shoffset(self):
        pass

    def get_shsize(self):
        pass

    def get_shlink(self):
        pass

    def get_shinfo(self):
        pass

    def get_shaddralign(self):
        pass

    def get_shentsize(self):
        pass


if __name__ == '__main__':

    e = Elf_Ehdr()

    if len(sys.argv) != 2:
        print "WRONG Dummy!"
    else:
        e.get_all_ehdr()
