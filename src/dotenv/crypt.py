import base64
import re
from typing import Optional

from cryptography.fernet import Fernet

ENCRYPTION_REGEX = r'^enc{(.+)}$'


class Crypt:

    @classmethod
    def is_encrypted_value(cls, value: Optional[str]) -> bool:
        return value is not None and not not re.match(ENCRYPTION_REGEX, value)

    @classmethod
    def _extract_encrypted_value(cls, value) -> Optional[str]:
        match = re.match(ENCRYPTION_REGEX, value)
        if match:
            return match.group(1)
        return None

    @classmethod
    def generate_key(cls) -> str:
        key_bytes = Fernet.generate_key()
        return base64.encodebytes(key_bytes).decode('utf-8')

    @classmethod
    def decrypt_value(cls, value: str, key: Optional[str]) -> str:
        if not key or not value:
            return value
        key_bytes = base64.decodebytes(key.encode('utf-8'))
        encrypted_value = cls._extract_encrypted_value(value)
        if not encrypted_value:
            return value
        value_bytes = base64.decodebytes(encrypted_value.encode('utf-8'))
        decrypted_bytes = Fernet(key=key_bytes).decrypt(value_bytes)
        return decrypted_bytes.decode('utf-8')

    @classmethod
    def encrypt_value(cls, value: str, key: str) -> str:
        key_bytes = base64.decodebytes(key.encode('utf-8'))
        encrypted_bytes = Fernet(key=key_bytes).encrypt(value.encode('utf-8'))
        return 'enc{' + base64.encodebytes(encrypted_bytes).decode('utf-8').strip().replace('\n', '') + '}'
