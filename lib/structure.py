import struct 
from formatError import FormatError

class StructureFormatError(FormatError):
    """Generic Structure format error exception."""

class Structure:
    """Prepare structure object to extract members from data.
    
    Format is a list containing definitions for the elements
    of the structure.
    """
    
    
    def __init__(self, format, name=None, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
#        self.values = {}
        self.__format_length__ = 0
        self.__set_format__(format[1])
        self._all_zeroes = False
        self.__unpacked_data_elms__ = None
        self.__file_offset__ = file_offset
        if name:
            self.name = name
        else:
            self.name = format[0]
                
            
    def __get_format__(self):
        return self.__format__
        
        
    def get_file_offset(self):
        return self.__file_offset__

    def set_file_offset(self, offset):
        self.__file_offset__ = offset
        
    def all_zeroes(self):
        """Returns true is the unpacked data is all zeroes."""
        
        return self._all_zeroes

                
    def __set_format__(self, format):
    
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type
                
                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [x[:len(elm_name)] for x in self.__keys__]
                        occ_count = search_list.count(elm_name)
                        elm_name = elm_name+'_'+str(occ_count)
                    names.append(elm_name)
                # Some PE header structures have unions on them, so a certain
                # value might have different names, so each key has a list of
                # all the possible members referring to the data.
                self.__keys__.append(names)
                    
        self.__format_length__ = struct.calcsize(self.__format__)
        
        
    def sizeof(self):
        """Return size of the structure."""
    
        return self.__format_length__
        
        
    def __unpack__(self, data):
    
        if len(data)>self.__format_length__:
            data = data[:self.__format_length__]
            
        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        elif len(data)<self.__format_length__:
            raise StructureFormatError('Data length less than expected header length.')

            
        if data.count(chr(0)) == len(data):
            self._all_zeroes = True
            
        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in range(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
#                self.values[key] = self.__unpacked_data_elms__[i]
                setattr(self, key, self.__unpacked_data_elms__[i])


    def __pack__(self):
    
        new_values = []
        
        for i in range(len(self.__unpacked_data_elms__)):
        
            for key in self.__keys__[i]:
                new_val = getattr(self, key)
                old_val = self.__unpacked_data_elms__[i]
                
                # In the case of Unions, when the first changed value
                # is picked the loop is exited
                if new_val != old_val:
                    break
                
            new_values.append(new_val)
            
        return struct.pack(self.__format__, *new_values)
        
                

    def dump(self, indentation=0):
        """Returns a string representation of the structure."""
    
        dump = []
        
        dump.append('[%s]' % self.name)

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, int) or isinstance(val, long):
                    val_str = '0x%-8X' % (val)
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s]' % time.ctime(val)
                        except exceptions.ValueError, e:
                            val_str += ' [INVALID TIME]'
                else:
                    val_str = ''.join(filter(lambda c:c != '\0', str(val)))

                dump.append('%-30s %s' % (key+':', val_str))

        return dump


class SectionStructure(Structure):
    """Convenience section handling class."""

    def get_data(self, start, length=None):
        """Get data chunk from a section.
        
        Allows to query data from the section by passing the
        addresses where the PE file would be loaded by default.
        It is then possible to retrieve code and data by its real
        addresses as it would be if loaded.
        """

        end = None
        offset = start - self.VirtualAddress

        if length:
            end = offset+length
        return self.data[offset:end]

    def get_offset_from_rva(self, rva):
        return (rva - self.VirtualAddress) + self.PointerToRawData

    def contains(self, address):
        """Check whether the section contains the address provided."""

        return address>=self.VirtualAddress and address<self.VirtualAddress+len(self.data)



