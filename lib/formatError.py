import exceptions


class FormatError(Exception):
    """Generic PE format error exception."""
    
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
