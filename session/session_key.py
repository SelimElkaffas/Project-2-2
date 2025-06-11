from datetime import datetime, timedelta

class SessionKey:
    def __init__(self, key_bytes, username, created_at=None, expires_at=None):
        self.key_bytes = key_bytes
        self.username = username
        self.created_at = created_at or datetime.now()
        self.expires_at = expires_at or (self.created_at + timedelta(seconds=15))  # Keys expire after 1 hour
    
    def is_expired(self):
        return datetime.now() > self.expires_at
    
    def get_key(self, allow_expired=False):
        if not allow_expired and self.is_expired():
            raise ValueError("Session key has expired.")
        return self.key_bytes
    
    def to_dict(self):
        return {
            'key_bytes': self.key_bytes.hex(),
            'username': self.username,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            key_bytes=bytes.fromhex(data['key_bytes']),
            username=data['username'],
            created_at=datetime.fromisoformat(data['created_at']),
            expires_at=datetime.fromisoformat(data['expires_at'])
        )
