from .base_anonymizer import BaseAnonymizer
import hashlib


class MD5Anonymizer(BaseAnonymizer):
    def __init__(self):
        pass

    def encode_data(self, input_data):
        encoded = input_data.encode()
        result = hashlib.md5(encoded).hexdigest()
        return result
