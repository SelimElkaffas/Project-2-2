import json
import os
from datetime import datetime, timedelta
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
        print(f"Adding key of size: {len(key_bytes)}, for user: {username}")
        return session_key
    
    def get_key(self, username, allow_expired=False):
        """Retrieve a user's session key, optionally allowing expired keys."""
        if username not in self.keys:
            raise KeyError(f"No session key found for user {username}")
        
        key = self.keys[username]
        if key.is_expired():
            if not allow_expired:
                raise ValueError(f"Session key for {username} has expired")
        return key.get_key(allow_expired=allow_expired)
    
    def remove_key(self, username):
        """Remove a user's session key."""
        if username in self.keys:
            del self.keys[username]
            self.save_keys()
    
    def cleanup_expired_keys(self, max_age_seconds=3600):
        """Remove all expired keys."""
        
        now = datetime.now()
        expired_usernames = [
            username for username, key in self.keys.items()
            if key.expires_at < now - timedelta(seconds=max_age_seconds)
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

    def is_key_espired(self, username):
        key = self.keys.get(username)
        return key.is_expired() if key else True

    def force_add_key(self, username, key_bytes):
        """Add or replace a session key and persist it."""
        session_key = SessionKey(key_bytes, username)
        self.keys[username] = session_key
        self.save_keys()
        print(f"[KEY_MANAGER]: Session key for {username} has been updated.")
        return session_key
