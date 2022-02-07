import shutil
import json
import os
import unittest
import logging
from pathlib import Path
from datadirtest import DataDirTester, TestDataDir
from keboola.component import CommonInterface


class PgpEncryptionTest(TestDataDir):
    def run_component(self):
        super().run_component()

    def setUp(self):
        super().setUp()
        source_out_files = os.path.join(self.data_dir, "source", "data", "out", "files")
        expected_out_files = os.path.join(self.data_dir, "expected", "data", "out", "files")
        source_out_tables = os.path.join(self.data_dir, "source", "data", "out", "tables")
        source_in_files = os.path.join(self.data_dir, "source", "data", "in", "files")
        Path(source_out_files).mkdir(parents=True, exist_ok=True)
        Path(source_in_files).mkdir(parents=True, exist_ok=True)
        Path(source_out_tables).mkdir(parents=True, exist_ok=True)
        Path(expected_out_files).mkdir(parents=True, exist_ok=True)
        self.ci = CommonInterface(data_folder_path=os.path.join(self.data_dir, "source", "data"))


class TestComponent(unittest.TestCase):

    def test_functional(self):
        functional_tests = DataDirTester(test_data_dir_class=PgpEncryptionTest)
        functional_tests.run()


if __name__ == "__main__":
    unittest.main()
