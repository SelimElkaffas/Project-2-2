import json
import os
from datetime import datetime
from .session_key import SessionKey

class SessionKeyManager:
    def __init__(self, storage_file="session_keys.json"):
        self.storage_file = storage_file
        self.keys = {}  # username -> SessionKey
        self.load_keys()
    
    def add_key(self, username, key_bytes):
        """Add a new session key for a user."""
        session_key = SessionKey(key_bytes, username)
        self.keys[username] = session_key
        self.save_keys()
        return session_key
    
    def get_key(self, username):
        """Get the session key for a user."""
        if username not in self.keys:
            raise KeyError(f"No session key found for user {username}")
        
        key = self.keys[username]
        if key.is_expired():
            del self.keys[username]
            self.save_keys()
            raise ValueError(f"Session key for {username} has expired")
        
        return key.get_key()
    
    def remove_key(self, username):
        """Remove a user's session key."""
        if username in self.keys:
            del self.keys[username]
            self.save_keys()
    
    def cleanup_expired_keys(self):
        """Remove all expired keys."""
        expired_usernames = [
            username for username, key in self.keys.items()
            if key.is_expired()
        ]
        for username in expired_usernames:
            del self.keys[username]
        if expired_usernames:
            self.save_keys()
    
    def save_keys(self):
        """Save all keys to the storage file."""
        data = {
            username: key.to_dict()
            for username, key in self.keys.items()
        }
        with open(self.storage_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_keys(self):
        """Load keys from the storage file."""
        if not os.path.exists(self.storage_file):
            return
        
        try:
            with open(self.storage_file, 'r') as f:
                data = json.load(f)
            
            self.keys = {
                username: SessionKey.from_dict(key_data)
                for username, key_data in data.items()
            }
            
            # Clean up expired keys on load
            self.cleanup_expired_keys()
        except Exception as e:
            print(f"Error loading session keys: {e}")
            self.keys = {}
