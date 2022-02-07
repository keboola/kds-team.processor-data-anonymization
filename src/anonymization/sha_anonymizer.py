from .base_anonymizer import BaseAnonymizer, AnonymizerException
import hashlib


class SHAAnonymizer(BaseAnonymizer):
    def __init__(self, sha_ver="512"):
        self.sha_ver = sha_ver

    def encode_data(self, input_data):
        encoded = input_data.encode()
        if self.sha_ver == "512":
            result = hashlib.sha512(encoded).hexdigest()
        elif self.sha_ver == "256":
            result = hashlib.sha256(encoded).hexdigest()
        else:
            raise AnonymizerException(f"{self.sha_ver} is not supported by SHAAnonymizer")
        return result
