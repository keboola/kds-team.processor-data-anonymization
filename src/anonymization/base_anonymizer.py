import abc


class AnonymizerException(Exception):
    pass


class BaseAnonymizer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def encode_data(self, input_data):
        pass
