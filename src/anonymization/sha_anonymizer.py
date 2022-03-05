from .base_anonymizer import Anonymizer, AnonymizerException
import hashlib


class SHAAnonymizer(Anonymizer):
    def __init__(self, sha_ver: str = "512") -> None:
        self.sha_ver = sha_ver

    def encode_data(self, input_data: str) -> str:
        encoded = input_data.encode()
        if self.sha_ver == "512":
            result = hashlib.sha512(encoded).hexdigest()
        elif self.sha_ver == "256":
            result = hashlib.sha256(encoded).hexdigest()
        else:
            raise AnonymizerException(f"{self.sha_ver} is not supported by SHAAnonymizer")
        return result
