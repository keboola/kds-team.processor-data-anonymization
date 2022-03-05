from .base_anonymizer import Anonymizer
import hashlib


class MD5Anonymizer(Anonymizer):
    def __init__(self) -> None:
        pass

    def encode_data(self, input_data: str) -> str:
        encoded = input_data.encode()
        result = hashlib.md5(encoded).hexdigest()
        return result
