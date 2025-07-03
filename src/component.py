import csv
import logging
import shutil
import sys
from pathlib import Path
import json
import os.path as pt
import os
import tempfile
import glob
from os import listdir, makedirs
from os.path import isfile, join
from anonymization import SHAAnonymizer, MD5Anonymizer, Anonymizer

from typing import List, Dict

from keboola.component.base import ComponentBase
from keboola.component.exceptions import UserException
from keboola.component.dao import TableDefinition, DataType, SupportedDataTypes
from typing import Any
from typing import Optional
from decompress import Decompressor, DecompressorException
import fnmatch

# type of anonymization/encryption : SHA, MD5, AES
KEY_ENCRYPT_METHOD = "method"
KEY_SALT = "#salt"
KEY_SALT_LOCATION = "salt_location"  # prepend, append

KEBOOLA_ZIPPED_EXTENSIONS: List[str] = [".gz"]
DEFAULT_SALT_LOCATION = "prepend"

KEY_TABLES = "tables_to_encrypt"

REQUIRED_PARAMETERS = [KEY_ENCRYPT_METHOD]
REQUIRED_IMAGE_PARS = []

# Increase the CSV field size limit
csv.field_size_limit(sys.maxsize)

class Component(ComponentBase):

    def __init__(self) -> None:
        super().__init__()

    def run(self) -> None:
        self.validate_configuration_parameters(REQUIRED_PARAMETERS)
        self.validate_image_parameters(REQUIRED_IMAGE_PARS)
        params = self.configuration.parameters

        salt = params.get(KEY_SALT, "")
        salt_location = params.get(KEY_SALT_LOCATION, DEFAULT_SALT_LOCATION)

        tables_to_anonymize = params.get(KEY_TABLES)

        # Check if files are in input instead of tables, give warning in the case of files
        self.check_for_files()
        # Move files from data/in/files to data/out/files
        self.move_files()

        for table in self.get_input_tables_definitions():
            anonymize = [pattern for pattern in tables_to_anonymize.keys() if fnmatch.fnmatch(table.name, pattern)]

            if len(anonymize) > 1:
                raise UserException(f"Multiple patterns found for table {table.name} in the configuration")
            elif anonymize:
                columns_to_anonymize = tables_to_anonymize.get(anonymize[0])
                self.anonymize_table(table.name, columns_to_anonymize, salt, salt_location)
            else:
                logging.info(f"Table '{table.name}' not specified in configuration, moving to output non-anonymized")
                out_table = self.create_out_table_definition(table.name)
                self.move_table_to_out(table, out_table)

    def anonymize_table(self, table_name: str, columns_to_anonymize: List, salt: str = "",
                        salt_location: str = ""):
        self.validate_column_params(columns_to_anonymize)
        in_table = self.get_input_table(table_name)

        if not in_table:
            logging.warning(f"Table : '{table_name}' is not in input tables")
            return

        in_table_manifest = self.get_table_manifest(in_table)
        write_columns_to_manifest = self.check_for_columns_in_manifest(in_table_manifest)
        table_has_headers = self.table_has_headers(in_table)

        if self.is_zipped_sliced_table(in_table):
            temp_file = self._unzip_sliced_table(in_table)
            in_table.full_path = temp_file
            self._anonymize_sliced_table(in_table,
                                         columns_to_anonymize,
                                         salt,
                                         salt_location,
                                         table_has_headers)
        elif self.is_sliced_table(in_table):
            self._anonymize_sliced_table(in_table,
                                         columns_to_anonymize,
                                         salt,
                                         salt_location,
                                         table_has_headers)
        else:
            self._anonymize_table(in_table,
                                  in_table.name,
                                  columns_to_anonymize,
                                  salt,
                                  salt_location,
                                  write_columns_to_manifest=write_columns_to_manifest,
                                  table_has_headers=table_has_headers)

    def get_table_columns(self, table: TableDefinition) -> List[str]:
        table_columns = table.column_names
        if not table_columns:
            table_columns = self._get_table_columns(table, table.delimiter)
        return table_columns

    @staticmethod
    def table_has_headers(table: TableDefinition) -> bool:
        if not table.column_names:
            return True
        return False

    @staticmethod
    def check_for_columns_in_manifest(table_manifest: Optional[Dict[str, Any]]) -> bool:
        write_columns_to_manifest = True
        if table_manifest:
            if not table_manifest.get("columns"):
                write_columns_to_manifest = False
        return write_columns_to_manifest

    @staticmethod
    def is_sliced_table(table: TableDefinition) -> bool:
        if pt.isdir(table.full_path):
            return True
        return False

    @staticmethod
    def is_zipped_sliced_table(table: TableDefinition) -> bool:
        if pt.isdir(table.full_path):
            for ext in KEBOOLA_ZIPPED_EXTENSIONS:
                if table.full_path.endswith(ext):
                    return True
        return False

    @staticmethod
    def get_table_manifest(table: TableDefinition) -> Optional[Dict[str, Any]]:
        manifest_path = "".join([table.full_path, ".manifest"])
        if pt.isfile(manifest_path):
            with open(manifest_path, 'r') as f:
                return json.load(f)
        return None

    @staticmethod
    def validate_column_params(columns: List[str]) -> None:
        if not isinstance(columns, list):
            raise UserException(f"The tables_to_encrypt config parameter must be key value pairs where the values"
                                f" are lists of columns not {type(columns)}")

    def _anonymize_sliced_table(self,
                                in_table: TableDefinition,
                                columns_to_anonymize: List[str],
                                salt: str,
                                salt_location: str,
                                table_has_headers: bool) -> None:

        out_table = self.create_out_table_definition_from_in_table(in_table,
                                                                   schema=in_table.schema)

        if not pt.exists(out_table.full_path):
            makedirs(out_table.full_path)

        sliced_files = self.get_sliced_files(in_table)
        for table_file in sliced_files:
            in_table_path = pt.join(in_table.full_path, table_file)
            out_table_path = pt.join(out_table.full_path, table_file)
            self._anonymize_table(in_table,
                                  table_file,
                                  columns_to_anonymize,
                                  salt,
                                  salt_location,
                                  write_manifest=False,
                                  in_table_path=in_table_path,
                                  out_table_path=out_table_path,
                                  table_has_headers=table_has_headers)

        self.update_schema(out_table, columns_to_anonymize)

        self.write_manifest(out_table)

    def update_schema(self, out_table: TableDefinition, columns_to_anonymize: List[str]) -> None:
        for column in columns_to_anonymize:
            if column in out_table.schema:
                old_datatype = out_table.schema.get(column).data_types.get("base")
                out_table.schema.get(column).update_datatype("base",
                                                             data_type=DataType(SupportedDataTypes.STRING,
                                                                                old_datatype.length,
                                                                                old_datatype.default))

    def _anonymize_table(self,
                         in_table: TableDefinition,
                         file_name: str,
                         columns_to_anonymize: List[str],
                         salt: str,
                         salt_location: str,
                         in_table_path: str = "",
                         out_table_path: str = "",
                         write_columns_to_manifest: bool = True,
                         write_manifest: bool = True,
                         table_has_headers: bool = True) -> None:

        if in_table.column_names:
            in_table_columns = in_table.column_names
        else:
            in_table_columns = self.get_table_columns(in_table)

        out_table = self.create_out_table_definition(file_name, schema=in_table.schema or in_table_columns)

        if in_table.destination:
            out_table.destination = in_table.destination

        if not in_table_path:
            in_table_path = in_table.full_path

        if not out_table_path:
            out_table_path = out_table.full_path

        if write_columns_to_manifest:
            out_table.schema = in_table.schema

        anonymizer = self.get_anonymizer()

        columns_to_anonymize = self.validate_columns_to_anonymize(columns_to_anonymize, in_table_columns, file_name)

        self.anonymize_columns(in_table_path, out_table_path, in_table_columns, salt, salt_location,
                               columns_to_anonymize, anonymizer, in_table.delimiter, table_has_headers,
                               write_columns_to_manifest)

        self.update_schema(out_table, columns_to_anonymize)

        if write_manifest:
            self.write_manifest(out_table)

    def create_out_table_definition_from_in_table(self,
                                                  in_table: TableDefinition,
                                                  schema) -> TableDefinition:

        out_table = self.create_out_table_definition(in_table.name,
                                                     schema=schema,
                                                     is_sliced=True,
                                                     incremental=in_table.incremental,
                                                     primary_key=in_table.primary_key,
                                                     table_metadata=in_table.table_metadata,
                                                     enclosure=in_table.enclosure,
                                                     delimiter=in_table.delimiter)
        if in_table.destination:
            out_table.destination = in_table.destination
        return out_table

    @staticmethod
    def get_sliced_files(table: TableDefinition) -> List[str]:
        return [f for f in listdir(table.full_path) if isfile(join(table.full_path, f))]

    def get_input_table(self, in_table_name: str) -> TableDefinition:
        in_tables = self.get_input_tables_definitions()
        return self.get_input_table_by_name(in_tables, in_table_name)

    @staticmethod
    def get_input_table_by_name(in_tables: List[TableDefinition], name: str) -> TableDefinition:
        for table in in_tables:
            if table.name == name:
                return table

    @staticmethod
    def validate_columns_to_anonymize(columns: List[str], table_columns: List[str], in_table_name: str) -> List[str]:
        columns_to_anonymize = []
        for column in columns:
            if column in table_columns:
                columns_to_anonymize.append(column)
            else:
                logging.warning(f"Column : '{column}' is not in the table {in_table_name}. "
                                f"Make sure all columns to anonymize are within the list : {table_columns}")
        return columns_to_anonymize

    @staticmethod
    def anonymize_columns(table_path: str,
                          out_table_path: str,
                          table_columns: List[str],
                          salt: str,
                          salt_location: str,
                          columns_to_anonymize: List[str],
                          anonymizer: Anonymizer,
                          delimiter: str,
                          table_has_headers: bool,
                          write_columns_to_manifest: bool) -> None:

        with open(table_path, "r") as in_file, open(out_table_path, "w") as out_file:
            csv_reader = csv.DictReader(in_file, fieldnames=table_columns, delimiter=delimiter)
            csv_writer = csv.DictWriter(out_file, fieldnames=table_columns, delimiter=delimiter)
            for i, row in enumerate(csv_reader):
                annonymized_row = row
                if table_has_headers and i == 0 and not write_columns_to_manifest:
                    csv_writer.writerow(annonymized_row)
                    continue
                if write_columns_to_manifest and table_has_headers and i == 0:
                    continue
                for column in columns_to_anonymize:
                    if salt_location == "prepend":
                        annonymized_row[column] = anonymizer.encode_data("".join([salt, row[column]]))
                    elif salt_location == "append":
                        annonymized_row[column] = anonymizer.encode_data("".join([row[column], salt]))
                csv_writer.writerow(annonymized_row)

    @staticmethod
    def _get_table_columns(table: TableDefinition, delimiter: str) -> List[str]:
        with open(table.full_path) as csv_file:
            csv_reader = csv.DictReader(csv_file, delimiter=delimiter)
            dict_from_csv = dict(list(csv_reader)[0])
            list_of_column_names = list(dict_from_csv.keys())
        return list_of_column_names

    def get_anonymizer(self) -> Anonymizer:
        params = self.configuration.parameters
        method = params.get(KEY_ENCRYPT_METHOD)
        if method in ["SHA", "SHA512"]:
            return SHAAnonymizer(sha_ver="512")
        elif method == "SHA256":
            return SHAAnonymizer(sha_ver="256")
        elif method == "MD5":
            return MD5Anonymizer()
        else:
            raise UserException(f"{method} method of anonymization/encryption is not supported, enter "
                                f"one from the list :  'SHA256', 'SHA512', 'MD5' ")

    def get_tables_not_in_list(self, list_of_tables: List[str]) -> List:
        input_tables = self.get_input_tables_definitions()
        tables_not_in_list = []
        for input_table in input_tables:
            if input_table.name not in list_of_tables:
                tables_not_in_list.append(input_table)
        return tables_not_in_list

    def check_for_files(self) -> None:
        in_files = self.get_input_files_definitions(only_latest_files=True)
        if in_files:
            logging.warning("Files found instead of tables, if you want them processed, "
                            "please first use the move files processor to move the files to tables. "
                            "For more information check the documentation")

    def move_files(self) -> None:
        files = self.get_input_files_definitions()
        for file in files:
            new_file = self.create_out_file_definition(file.name)
            if pt.isfile(file.full_path):
                shutil.copy(file.full_path, new_file.full_path)
            elif pt.isdir(file.full_path):
                shutil.copytree(file.full_path, new_file.full_path, dirs_exist_ok=True)

    def move_table_to_out(self, source, destination):
        if pt.isfile(source.full_path):
            shutil.copy(source.full_path, destination.full_path)
        elif pt.isdir(source.full_path):
            shutil.copytree(source.full_path, destination.full_path, dirs_exist_ok=True)
        if Path(f'{source.full_path}.manifest').exists():
            shutil.copy(f'{source.full_path}.manifest', f'{destination.full_path}.manifest')
        else:
            self.write_manifest(destination)

    def _unzip_sliced_table(self, table: TableDefinition):
        d = Decompressor()
        temp_dir = tempfile.mkdtemp()
        sliced_files = self._get_in_files(table.full_path)
        for sliced_file in sliced_files:
            sliced_file_out = self._get_out_path(sliced_file, temp_dir)
            try:
                d.decompress(sliced_file, sliced_file_out)
            except DecompressorException as decompress_exc:
                raise UserException(decompress_exc) from decompress_exc

        temp_file_loc = os.path.join(temp_dir, table.name)
        return temp_file_loc

    @staticmethod
    def _get_in_files(table_path) -> list:
        files = glob.glob(os.path.join(table_path, "**/*"), recursive=True)
        return [f for f in files if not os.path.isdir(f)]

    def _get_out_path(self, filepath, temp_dir_name) -> str:
        filename, relative_dir = self._get_filename_from_path(filepath)
        folder_name, relative_dir = self._get_filename_from_path(relative_dir, remove_ext=False)
        out_path = os.path.join(temp_dir_name, folder_name)
        return out_path

    def _get_filename_from_path(self, file_path, remove_ext=True) -> [str, str]:
        relative_dir = os.path.dirname(file_path).replace(self.files_in_path, '').lstrip('/').lstrip('\\')
        filename = os.path.basename(file_path)
        if remove_ext:
            filename = filename.split(".")[0]
        return filename, relative_dir


if __name__ == "__main__":
    try:
        comp = Component()
        # this triggers the run method by default and is controlled by the configuration.action parameter
        comp.execute_action()

    except UserException as exc:
        logging.exception(exc)
        exit(1)
    except Exception as exc:
        logging.exception(exc)
        exit(2)
