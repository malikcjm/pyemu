
"""pefile, Portable Executable reader module
the root of the distribution archive.
"""

__author__ = 'Kamil Zbrog'
__version__ = '0.0.1'
__contact__ = 'kamil@zbrog.org'

import os
import time
import exceptions
from dump import Dump
from structure import Structure
from formatError import FormatError

IMAGE_DOS_SIGNATURE             = 0x5A4D
IMAGE_NE_SIGNATURE              = 0x454E

class NEFormatError(FormatError):
    """Generic NE format error exception."""
    

ne_segment_flags = [
('NE_SEGFLAGS_DATA',       0x0001),
('NE_SEGFLAGS_ALLOCATED',  0x0002),
('NE_SEGFLAGS_LOADED',     0x0004),
('NE_SEGFLAGS_ITERATED',   0x0008),
('NE_SEGFLAGS_MOVEABLE',   0x0010),
('NE_SEGFLAGS_SHAREABLE',  0x0020),
('NE_SEGFLAGS_PRELOAD',    0x0040),
('NE_SEGFLAGS_EXECUTEONLY',0x0080),
('NE_SEGFLAGS_READONLY',   0x0080),
('NE_SEGFLAGS_RELOC_DATA', 0x0100),
('NE_SEGFLAGS_SELFLOAD',   0x0800),
('NE_SEGFLAGS_DISCARDABLE',0x1000),
('NE_SEGFLAGS_32BIT',      0x2000) ]

NE_SEGFLAGS = dict([(e[1], e[0]) for e in
    ne_segment_flags]+ne_segment_flags)


class NE:
    """ A New Executable representation
    """

    __IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER',
        ('H,e_magic', 'H,e_cblp', 'H,e_cp',
        'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc',
        'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum',
        'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res',
        'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
        'L,e_lfanew'))

    __IMAGE_NE_HEADERS_format__ = ('IMAGE_NE_HEADERS', ('H,Signature',))

    __IMAGE_WIN_HEADER_format__ = ('IMAGE_WIN_HEADER', 
        ('B,LinkerVersion', 'B,LinkerRevision',
         'H,EntryTableOffset', 'H,EntryTableSize',
         'I,FileLoadCRC', 'B,ProgramFlags', 'B,ApplicationFlags',
         'H,AutoDataSegmentIndex', 'H,InitialLocalHeapSize', 'H,InitialStackSize',
         'H,InitialIP', 'H,InitialCS', 'H,InitialSP', 'H,InitialSS',
         'H,SegmentTableEntryCount', 'H,ModuleTableEntryCount',
         'H,NonresidentNameTableSize', 'H,SegmentTableOffset',
         'H,ResourceTableOffset', 'H,ResidentNameTableOffset',
         'H,ModuleReferenceTableOffset', 'H,ImportTableOffset',
         'I,NonResidentTableOffset', 'H,MovableEntryPointCount',
         'H,Aligment', 'H,ReservedSegmentCount', 'B,TargetOS',
         'B,MiscFlags','H,FastLoadOffset', 'H,FastLoadSize',
         'H,Reserved', 'B,WindowsRevision', 'B,WindowsVersion'
        ))

    __IMAGE_SEGMENT_HEADER_format__ = ('IMAGE_SEGMENT_HEADER',
        ('H,Offset', 'H,Length', 'H,Flags', 'H,MinAllocSize'))

    def __init__(self, name=None, data=None):
        self.sections = []

        # This list will keep track of all the structures created.
        # That will allow for an easy iteration through the list
        # in order to save the modifications made
        self.__structures__ = []


        self.__parse__(name, data)


    def __unpack_data__(self, format, data, file_offset):
        """Apply structure format to raw data.
        
        Returns and unpacked structure object if successful, None otherwise.
        """
    
        structure = Structure(format, file_offset=file_offset)
        if len(data) < structure.sizeof():
            return None
    
        structure.__unpack__(data)
        self.__structures__.append(structure)
    
        return structure


    def __parse__(self, fname, data):
        """Parse a New Executable file.
        
        Loads a NE file, parsing all its structures and making them available
        through the instance's attributes.
        """
       
        if fname:
            fd = file(fname, 'rb')
            self.__data__ = fd.read()
            fd.close()
        elif data:
            self.__data__ = data
            
        self.DOS_HEADER = self.__unpack_data__(
            self.__IMAGE_DOS_HEADER_format__,
            self.__data__, file_offset=0)
            
        if not self.DOS_HEADER or self.DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
            raise NEFormatError('DOS Header magic not found.')

        ne_headers_offset = self.DOS_HEADER.e_lfanew

        self.NE_HEADERS = self.__unpack_data__(
            self.__IMAGE_NE_HEADERS_format__,
            self.__data__[ne_headers_offset:],
            file_offset = ne_headers_offset)

        if not self.NE_HEADERS or not self.NE_HEADERS.Signature:
            raise NEFormatError('NE Headers not found.')

        if self.NE_HEADERS.Signature != IMAGE_NE_SIGNATURE:
            raise NEFormatError('Invalid NE Headers signature.')

        self.WIN_HEADER = self.__unpack_data__(
            self.__IMAGE_WIN_HEADER_format__,
            self.__data__[ne_headers_offset+2:],
            file_offset = ne_headers_offset+2)

        if not self.WIN_HEADER:
            raise NEFormatError('Win Header missing')

        segment_table_offset = self.WIN_HEADER.SegmentTableOffset + ne_headers_offset

        self.segmentTable = []

        for i in range(self.WIN_HEADER.SegmentTableEntryCount):
            segment = self.__unpack_data__(
                self.__IMAGE_SEGMENT_HEADER_format__,
                self.__data__[segment_table_offset+8*i:],
                file_offset = segment_table_offset+8*i)
            self.segmentTable.append(segment)

    def retrieve_flags(self, flag_dict, flag_filter):
        """Read the flags from a dictionary and return them in a usable form.
        
        Will return a list of (flag, value) for all flags in "flag_dict"
        matching the filter "flag_filter".
        """
        
        return [(f[0][len(flag_filter):], f[1]) for f in flag_dict.items() if
                isinstance(f[0], str) and f[0].startswith(flag_filter)]

 

    def __str__(self):
        return self.dump_info()
    
            
    def print_info(self):
        """Print all the PE header information in a human readable from."""

        print self.dump_info()
        
        
    def dump_info(self):
        """Dump all the PE header information into human readable string."""
        
        
        dump = Dump()
        
        dump.add_header('DOS_HEADER')
        dump.add_lines(self.DOS_HEADER.dump())
        dump.add_newline()

        dump.add_header('NE_HEADERS')
        dump.add_lines(self.NE_HEADERS.dump())
        dump.add_newline()

        dump.add_header('WIN_HEADER')
        dump.add_lines(self.WIN_HEADER.dump())
        dump.add_newline()

        dump.add_header('NE Segments')
        segment_flags = self.retrieve_flags(NE_SEGFLAGS, 'NE_SEGFLAGS_')
        for segmentTableEntry in self.segmentTable:
            dump.add_lines(segmentTableEntry.dump())
            dump.add('Flags: ')
            flags = []
            for flag in segment_flags:
                if segmentTableEntry.Flags & flag[1]:
                    flags.append(flag[0])
            dump.add_line(', '.join(flags))
            dump.add_line('File pos %08X' % (segmentTableEntry.Offset << self.WIN_HEADER.Aligment))
            dump.add_newline()

        return dump.get_text()
 
