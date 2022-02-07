Data Anonymization Processor
=============

This processor enables you to anonymize specified columns of an input table.

**Table of contents:**

[TOC]

Supported anonymization methods
===================

- SHA (512)
- MD5

If you need more anonymization methods, please submit your request to
[ideas.keboola.com](https://ideas.keboola.com/)

Configuration
=============
- method : method of anonymization (possible : "MD5", "SHA")
- tables_to_encrypt : dictionary of tables and their columns to encrypt, eg. {"table_name.csv" : ["column_1_in_table_name.csv",column_2_in_table_name.csv"]}


Sample Configuration
=============

```json
{
  "parameters": {
    "method": "MD5",
    "tables_to_encrypt": {
      "test.csv": [
        "Email",
        "Name"
      ]
    }
  }
}
```

Output
======

The anonymized tables will be sent to out/tables with the same name as they have in in/tables

Development
-----------

If required, change local data folder (the `CUSTOM_FOLDER` placeholder) path to your custom path in
the `docker-compose.yml` file:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    volumes:
      - ./:/code
      - ./CUSTOM_FOLDER:/data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Clone this repository, init the workspace and run the component with following command:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
git clone https://bitbucket.org/kds_consulting_team/kds-team.processor-data-anonymization/src/master/ dkds-team.processor-data-anonymization
cd dkds-team.processor-data-anonymization
docker-compose build
docker-compose run --rm dev
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run the test suite and lint check using this command:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
docker-compose run --rm test
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Integration
===========

For information about deployment and integration with KBC, please refer to the
[deployment section of developers documentation](https://developers.keboola.com/extend/component/deployment/)
