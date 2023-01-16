import os
import pathlib
import re
import shutil

import gzip
from py7zr import unpack_7zarchive

SUPPORTED_FORMATS = [
    ".7z", ".tar.bz2", ".tbz2", ".gz", ".tar.gz", ".tgz", ".tar", ".tar.xz", ".txz", ".zip"
]


def gunzip(gzipped_file_name, work_dir) -> None:
    """gunzip the given gzipped file"""

    filename = os.path.split(gzipped_file_name)[-1]
    filename = re.sub(r"\.gz$", "", filename, flags=re.IGNORECASE)

    if not os.path.exists(work_dir):
        os.makedirs(work_dir)

    with gzip.open(gzipped_file_name, 'rb') as f_in:
        with open(os.path.join(work_dir, filename), 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)


class DecompressorException(Exception):
    pass


class Decompressor:
    def __init__(self):
        shutil.register_unpack_format("7zip",
                                      [".7z"],
                                      unpack_7zarchive,
                                      description="7zip archive")

        shutil.register_unpack_format("gz", [".gz", ], gunzip)

    def decompress(self, file_path, file_out_path) -> None:
        """
        If the file in file_path is of supported type, unzips the file into file_out_path.
        Args:
            file_path: Path of the file to unzip.
            file_out_path: Path where file/files will be unzipped to.

        Returns:
            None
        """

        if self._is_supported_filetype(file_path):
            shutil.unpack_archive(file_path, file_out_path)
        else:
            raise DecompressorException(f"File {file_path} cannot be processed: unsupported file type.")

    @staticmethod
    def _is_supported_filetype(file_path) -> bool:
        """
        Returns True/False based on filetypes defined in SUPPORTED_FORMATS.
        Args:
            file_path: Path of the file to unzip.

        Returns:
            bool

        """
        extension = pathlib.Path(file_path).suffix
        if extension not in SUPPORTED_FORMATS:
            extensions = pathlib.Path(file_path).suffixes[-2:]
            extension = "".join(extensions)
            if extension not in SUPPORTED_FORMATS:
                return False
        return True

    @staticmethod
    def unregister_formats() -> None:
        """
        Unregisters formats that register_formats method registered.
        This exists for easier test writing because shutil returns RegistryError
        when trying to register already registered format.
        """
        shutil.unregister_unpack_format("7zip")
        shutil.unregister_unpack_format("gz")
