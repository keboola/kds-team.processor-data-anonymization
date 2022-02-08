import csv
import logging
import shutil
from pathlib import Path
from anonymization import SHAAnonymizer, MD5Anonymizer

from keboola.component.base import ComponentBase
from keboola.component.exceptions import UserException

# type of anonymization/encryption : SHA, MD5, AES
KEY_ENCRYPT_METHOD = "method"

KEY_TABLES = "tables_to_encrypt"

REQUIRED_PARAMETERS = [KEY_ENCRYPT_METHOD]
REQUIRED_IMAGE_PARS = []


class Component(ComponentBase):

    def __init__(self):
        super().__init__()

    def run(self):
        self.validate_configuration_parameters(REQUIRED_PARAMETERS)
        self.validate_image_parameters(REQUIRED_IMAGE_PARS)
        params = self.configuration.parameters

        in_tables = params.get(KEY_TABLES)

        non_anonymized_tables = self.get_tables_not_in_list(list(in_tables.keys()))
        self.move_tables(non_anonymized_tables)

        for table_name in in_tables:
            columns = in_tables[table_name]
            in_table = self.get_input_table(table_name)
            if in_table:
                self.anonymize_file(in_table, columns)
            else:
                logging.warning(f"Table : '{table_name}' is not in input tables")

    def anonymize_file(self, in_table, columns):
        out_table = self.create_out_table_definition(in_table.name)

        table_columns = self.get_table_columns(in_table)
        out_table.columns = table_columns

        anonymizer = self.get_anonymizer()

        columns_to_anonymize = self.validate_columns_to_anonymize(columns, table_columns, in_table.name)

        self.anonymize_columns(in_table, out_table, table_columns, columns_to_anonymize, anonymizer)
        self.write_manifest(out_table)

    def get_input_table(self, in_table_name):
        in_tables = self.get_input_tables_definitions()
        return self.get_input_table_by_name(in_tables, in_table_name)

    @staticmethod
    def get_input_table_by_name(in_tables, name):
        for table in in_tables:
            if table.name == name:
                return table

    @staticmethod
    def validate_columns_to_anonymize(columns, table_columns, in_table_name):
        columns_to_anonymize = []
        for column in columns:
            if column in table_columns:
                columns_to_anonymize.append(column)
            else:
                logging.warning(f"Column : '{column}' is not in the table {in_table_name}. "
                                f"Make sure all columns to anonymize are within the list : {table_columns}")
        return columns_to_anonymize

    @staticmethod
    def anonymize_columns(in_table, out_table, table_columns, columns_to_anonymize, anonymizer):
        with open(in_table.full_path, "r") as in_file, open(out_table.full_path, "w") as out_file:
            csv_reader = csv.DictReader(in_file)
            csv_writer = csv.DictWriter(out_file, fieldnames=table_columns)
            for i, row in enumerate(csv_reader):
                annonymized_row = row
                for column in columns_to_anonymize:
                    annonymized_row[column] = anonymizer.encode_data(row[column])
                csv_writer.writerow(annonymized_row)

    @staticmethod
    def get_table_columns(table):
        with open(table.full_path) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            dict_from_csv = dict(list(csv_reader)[0])
            list_of_column_names = list(dict_from_csv.keys())
        return list_of_column_names

    def get_anonymizer(self):
        params = self.configuration.parameters
        method = params.get(KEY_ENCRYPT_METHOD)
        if method == "SHA":
            return SHAAnonymizer()
        elif method == "MD5":
            return MD5Anonymizer()
        else:
            raise UserException(f"{method} of anonymization/encryption is not supported, enter one from the list :"
                                f" 'SHA', 'MD5' ")

    def get_tables_not_in_list(self, list_of_tables):
        input_tables = self.get_input_tables_definitions()
        tables_not_in_list = []
        for input_table in input_tables:
            logging.info(f"Table : {input_table.name} in loc : {input_table.full_path}")
            if input_table.name not in list_of_tables:
                tables_not_in_list.append(input_table)
        return tables_not_in_list

    def move_tables(self, non_anonymized_tables):
        for table in non_anonymized_tables:
            logging.info(f"Table '{table.name}' not specified in configuration, moving to output non-anonymized")
            out_table = self.create_out_table_definition(table.name)
            self.move_file_to_out(table, out_table)

    def move_file_to_out(self, source, destination):
        shutil.copy(source.full_path, destination.full_path)
        if Path(f'{source.full_path}.manifest').exists():
            shutil.copy(f'{source.full_path}.manifest', f'{destination.full_path}.manifest')
        else:
            # destination.columns = self.get_table_columns(destination)
            self.write_manifest(destination)


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
