"""Sample models — this file is NOT in write_scope for most demos."""


class User:
    def __init__(self, name: str, is_active: bool = True, role: str = "user"):
        self.name = name
        self.is_active = is_active
        self.role = role
        self.session_token = None
