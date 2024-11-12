from enum import Enum, auto

class AuthLevel(Enum):
    """Authentication levels for the application"""
    NONE = auto()
    PASSWORD_ONLY = auto()
    PASSWORD_TOTP = auto()