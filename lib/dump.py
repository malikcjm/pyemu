class Dump:
    """Convenience class for dumping the PE information."""
    
    def __init__(self):
        self.text = ''
    
        
    def add_lines(self, txt, indent=0):
        """Adds a list of lines.
        
        The list can be indented with the optional argument 'indent'.
        """
        for line in txt:
            self.add_line(line, indent)
        
            
    def add_line(self, txt, indent=0):
        """Adds a line.
        
        The line can be indented with the optional argument 'indent'.
        """
        
        self.add(txt+'\n', indent)
    
        
    def add(self, txt, indent=0):
        """Adds some text, no newline will be appended.
        
        The text can be indented with the optional argument 'indent'.
        """
        
        if isinstance(txt, unicode):
            s = []
            for c in txt:
                try:
                    s.append(str(c))
                except UnicodeEncodeError, e:
                    s.append(repr(c))
            txt = ''.join(s)
        
        self.text += ' '*indent+txt
    
        
    def add_header(self, txt):
        """Adds a header element."""
        
        self.add_line('-'*10+txt+'-'*10+'\n')
        
        
    def add_newline(self):
        """Adds a newline."""
        
        self.text += '\n'
        
        
    def get_text(self):
        """Get the text in its current state."""
    
        return self.text



