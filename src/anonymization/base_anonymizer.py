import abc


class AnonymizerException(Exception):
    pass


class Anonymizer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def encode_data(self, input_data):
        pass
