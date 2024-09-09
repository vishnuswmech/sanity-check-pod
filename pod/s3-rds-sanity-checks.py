import logging
import psycopg2
import re
import datetime
import pytz
from configparser import ConfigParser
import os
import subprocess
import csv
from botocore.exceptions import ClientError
import boto3
import glob
import traceback
import sys
file_pattern = '*.log'
current_directory = os.getcwd()

class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    green = "\x1b[32;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    datefmt='%m/%d/%Y %I:%M:%S %p'
    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt,datefmt=self.datefmt)
        return formatter.format(record)
# create logger with 'sanity check application'
logger = logging.getLogger("Sanity Checks")
logger.setLevel(logging.DEBUG)

#create filehandler for logging
# Create a formatter with IST time
class ISTFileFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ist_timezone = pytz.timezone('Asia/Kolkata')  # IST timezone
        ist_datetime = datetime.datetime.now(ist_timezone)
        return ist_datetime.strftime("%Y_%m_%d_%H_%M_%S_IST")
fileformatter = ISTFileFormatter('%(asctime)s - sanity checks - %(levelname)s - %(message)s')

current_datetime = datetime.datetime.now(pytz.utc)
ist_timezone = pytz.timezone('Asia/Kolkata')
ist_datetime = datetime.datetime.now(ist_timezone)
suffix = ist_datetime.strftime("_%Y_%m_%d_%H_%M_%S_IST")
code_execution_log_file = f"infra_sanity_checks_{suffix}.log"
error_execution_log_file = f"{code_execution_log_file}"

for file_path in glob.glob(os.path.join(current_directory, file_pattern)):
    try:
        logger.info("Removing .log file files")
        os.remove(file_path)
        logger.info(".log files were removed successfully")

    except OSError:
        logger.info(".log files doesnot exist, so passing...")
        pass



filehandler = logging.FileHandler(code_execution_log_file)

filehandler.rotation = "100 MB"
logger.addHandler(filehandler)
filehandler.setLevel(logging.DEBUG)
filehandler.setFormatter(fileformatter)


# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())

logger.addHandler(ch)

#IST timezone suffix
current_datetime = datetime.datetime.now(pytz.utc)
ist_timezone = pytz.timezone('Asia/Kolkata')
ist_datetime = datetime.datetime.now(ist_timezone)
suffix = ist_datetime.strftime("_%Y_%m_%d_%H_%M_%S_IST")


def exception_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Log the exception using traceback
            logging.error("An error occurred in %s: %s", func.__name__, traceback.format_exc())
            logger.info(f"The log file name is {error_execution_log_file} and bucket is {s3_bucket}")
            # Upload the error log file to S3
            send_to_s3(error_execution_log_file, s3_bucket)

            # Re-raise the exception to maintain program flow
            raise

    return wrapper

@exception_handler
def send_to_s3(error_execution_log_file,s3_bucket):
    # Upload the csv file to the bucket
    #error_log_file
    try:
        bucket_location = f"infra_sanity_checks/error_logs_file/{error_execution_log_file}"
        logger.info(f"The bucket location is {bucket_location}")
        s3.meta.client.upload_file(error_execution_log_file, s3_bucket, bucket_location)
        logger.info(f"The error log file {error_execution_log_file} was successfully uploaded to the bucket '{s3_bucket}'.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            logger.error(f"Access denied to write to the bucket '{s3_bucket}': {e}")
            logger.info(f"Make sure you have write access to the bucket {s3_bucket}.")
            logger.info(f"Error log file was not able to write on the s3 bucket {s3_bucket}")
            raise Exception(f"Access denied to write to the bucket '{s3_bucket}': {e}")
        else:
            logger.info(f"Error log file was not able to write on the s3 bucket {s3_bucket}")
            logger.error(f"Error occurred while uploading the error log file to the bucket '{s3_bucket}': {e}")
            raise Exception(f"Error occurred while uploading the error log file to the bucket '{s3_bucket}': {e}")
@exception_handler
def check_special_characters(password):
    reserved_characters = r':/?#[]@!$&\'()*+,;='
    pattern = re.compile(f'[{re.escape(reserved_characters)}]')

    #reference https://datatracker.ietf.org/doc/html/rfc3986#section-2.2

    if re.search(pattern, password):
        return True
    return False

# instantiate
#config = ConfigParser()

# parse existing file
#config.read('config.ini')
#db_cred = list(config.items('db'))
#db_host= config.get("db","db_host")
#db_port= config.get("db","db_port")
#db_user= config.get("db","db_user")
#db_password = config.get("db","db_password")
#db_name= config.get("db","db_name")
#log_level = config.get("db","log_level")
#csv_file_name_raw = config.get("db","csv_file_name")

#s3_bucket = config.get("s3","s3_bucket")
#region = config.get("s3","region")
db_host = os.environ.get("db_host")
db_port = os.environ.get("db_port")
db_user = os.environ.get("db_user")
db_password = os.environ.get("db_password")
db_name = os.environ.get("db_name")
log_level = os.environ.get("log_level")
csv_file_name_raw = os.environ.get("csv_file_name_raw")
s3_bucket = os.environ.get("s3_bucket")
region = os.environ.get("region")




#removing any .log files if already exists
#try:
    # Attempt to remove the file(s)
#    os.remove('*.log')
#except:
    # Log the error message
#    logging.info("There is no log files with .log suffix exists..so passing now")


#printing the env details
logger.info(f"The DB user is {db_user}")
logger.info(f"The DB port is {db_port}")
logger.info(f"The DB host is {db_host}")
logger.info(f"The DB name is {db_name}")
logger.info(f"The raw CSV file name is {csv_file_name_raw}")

logger.info(f"The bucket name is {s3_bucket}")
logger.info(f"The bucket region is {region}")



csv_file_name = f"csv_file_name_raw_{suffix}"
logger.info(f"The CSV file name is {csv_file_name}")


s3 = boto3.resource('s3')
#checking DB access
try:
        connection = psycopg2.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name,
            connect_timeout=5
        )
        logger.info(f"Connected to the Aurora PostgreSQL database '{db_name}'")
except psycopg2.OperationalError as e:
        logger.error(f"Failed to connect to the Aurora PostgreSQL database '{db_name}': {e}")
        logger.info("Make sure the database credentials are correct and the database is running.")
        #logging.error("An error occurred: %s", traceback.format_exc())
        #send_to_s3(error_execution_log_file, s3_bucket)
        send_to_s3 = exception_handler(send_to_s3)
        send_to_s3(error_execution_log_file,s3_bucket)
        #raise Exception(f"Failed to connect to the Aurora PostgreSQL database '{db_name}': {e}")
        
@exception_handler
def upload_csv_to_s3(csv_file_name,s3_bucket):
    try:
        logger.info("The S3 sanity checks going to start...")
        # Create the CSV file
        data = [
            ['event_id', 'event_name', 'event_value'],
            ['550e8400-e29b-41d4-a716-446655440000', 'product_view', 'coffee mug'],
            ['123e4567-e89b-12d3-a456-426655440000', 'search', 'coffee filters'],
            ['abcdef12-3456-7890-abcd-ef1234567890', 'product_view', 'french press']
        ]

        with open(csv_file_name, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(data)

        # Upload the file to S3

    except Exception as e:
        logger.error(f"Error occurred while uploading csv file: {e}")
        send_to_s3 = exception_handler(send_to_s3)
        send_to_s3(error_execution_log_file,s3_bucket)

        raise Exception(f"Error occurred while uploading csv file: {e}")
    # Upload the csv file to the bucket
    try:
        s3.meta.client.upload_file(csv_file_name, s3_bucket,csv_file_name)
        logger.info(f"The csv file {csv_file_name} was successfully uploaded to the bucket '{s3_bucket}'.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            logger.error(f"Access denied to write to the bucket '{s3_bucket}': {e}")
            logger.info(f"Make sure you have write access to the bucket {s3_bucket}.")
            raise Exception(f"Access denied to write to the bucket '{s3_bucket}':{e}")
        else:
            logger.error(f"Error occurred while uploading the file to the bucket '{s3_bucket}': {e}")
            raise Exception(f"Error occurred while uploading the file to the bucket '{s3_bucket}': {e}")
@exception_handler
def check_rds_access(db_host, db_port, db_user, db_password, db_name, log_level):

    # Check read access by fetching a record from a table
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        logger.info("Read access to the database is successful")
        logger.info(f"Sample record: {result}")
    except psycopg2.Error as e:
        logger.error(f"Failed to read from the Aurora PostgreSQL database '{db_name}': {e}")
        if e.pgcode == '42P01':
            logger.error("The table does not exist. Make sure the table is created in the database.")
            logger.info("Recommendation: Create the required table in the database.")
            raise Exception(f"The table does not exist. Make sure the table is created in the database : {e}")
        elif e.pgcode == '3D000':
            logger.error("The database does not exist. Make sure the correct database name is provided.")
            logger.info("Recommendation: Check the database name and create the database if it does not exist.")
            raise Exception(f"The database does not exist. Make sure the correct database name is provided : {e}")
        else:
            logger.error("An error occurred while reading from the database. Check the error details and try again.")
            logger.info("Recommendation: Verify the database connection details and ensure the database is accessible.")
            raise Exception(f"An error occurred while reading from the database. Check the error details and try again. {e}")
    finally:
        cursor.close()

    # Check write access by creating a new schema

    schema_name = f"infraTestSchema{suffix}"
    table_name = f"infraTestTable{suffix}"
    try:
        cursor = connection.cursor()
        create_schema_query = f"""
    CREATE schema {schema_name}
"""
        cursor.execute(create_schema_query)
        # Check if table creation occurred
        # Commit the changes Committing the changes is an essential step to ensure data integrity and durability.
        try:
          connection.commit()
          logger.info('Changes committed')
        except psycopg2.Error as e:
          logger.error(f'Error committing changes: {e}')
          cursor.close()
          connection.close()
          raise Exception(f'Error committing changes: {e}')
        logger.info("Schema creation access to the database is successful")
    except psycopg2.Error as e:
        logger.error(f"Failed to write to the Aurora PostgreSQL database '{db_name}': {e}")
        raise Exception(f"Failed to write to the Aurora PostgreSQL database '{db_name}': {e}")
    finally:
        cursor.close()
    # check write access by creating a table in newly created schema
    try:
        cursor = connection.cursor()
        create_table_query = f"""
    CREATE TABLE {schema_name}.{table_name} (
 id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL
    )
"""
        cursor.execute(create_table_query)
# Commit the changes Committing the changes is an essential step to ensure data integrity and durability.
        try:
          connection.commit()
          logger.info('Changes committed')
        except psycopg2.Error as e:
          logger.error(f'Error committing changes: {e}')
          cursor.close()
          connection.close()
          raise Exception(f'Error committing changes: {e}')

        logger.info(f"{table_name} was created successfully under {schema_name}")
        logger.info("Write access to the database is successful")
    except psycopg2.Error as e:
        logger.error(f"Failed to write to the Aurora PostgreSQL database '{db_name}': {e}")
        if e.pgcode == '3F000':
            logger.error(f"The {schema_name} does not exist. Make sure the {schema_name} is created in the database.")
            logger.info("Recommendation: Create the required schema in the database.")
            raise Exception(f"The {schema_name} does not exist. Make sure the {schema_name} is created in the database: {e}")
        else:
            logger.error("An error occurred while writing to the database. Check the error details and try again.")
            logger.info("Recommendation: Verify the database connection details and ensure the database is accessible.")
            raise Exception(f"An error occurred while writing to the database. Check the error details and try again.: {e}")
    finally:
        cursor.close()
    # delete the sanity test schema and table
    try:
        cursor = connection.cursor()
        delete_schema_query = f"""
     DROP SCHEMA {schema_name} CASCADE
"""
        cursor.execute(delete_schema_query)
                # Commit the changes Committing the changes is an essential step to ensure data integrity and durability.
        try:
          connection.commit()
          logger.info('Changes committed')
        except psycopg2.Error as e:
          logger.error(f'Error committing changes: {e}')
          cursor.close()
          connection.close()
          raise Exception(f'Error committing changes: {e}')

        logger.info(f"{schema_name} was deleted successfully along with {table_name}")
    except psycopg2.OperationalError as e:
        logger.error(f"Failed to delete the schema : {e}")
        logger.info(f"Unable to delete the schema {schema_name}, check the schema_name whether exists in DB")
        raise Exception(f"Failed to delete the schema : {e}")
        connection.close()

@exception_handler
def import_data_from_s3():
    # Create a cursor
    try:
        cursor = connection.cursor()
    except psycopg2.Error as e:
        logger.error(f'Error creating a cursor: {e}')
        connection.close()
        raise Exception(f'Error creating a cursor: {e}')

     # Execute the extension creation query
    try:
        #logger.info("Deleting extension if exists")
        #cursor.execute("DROP EXTENSION IF EXISTS aws_s3 CASCADE")
        #logger.info("Extension deletion done")
        os.environ["PGPASSWORD"] = db_password
        select_cmd = f'psql -h {db_host} -d {db_name} -U {db_user} -c "SELECT * FROM pg_extension;"'
        output = subprocess.check_output(select_cmd, shell=True)
        logger.info("Extension details:\n%s", output.decode())
        cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'aws_s3';")
        result = cursor.fetchone()
        if result is not None:
            #Extension already exists
            logger.info("Extension aws_s3 already exists,so dropping now")
        else:
            logger.info("aws_s3 extension not there, creating now......")
            cursor.execute("CREATE EXTENSION if not exists aws_s3 CASCADE")
            logger.info('Extension created: aws_s3')
        select_cmd = f'psql -h {db_host} -d {db_name} -U {db_user} -c "SELECT * FROM pg_extension;"'
        output = subprocess.check_output(select_cmd, shell=True)
        logger.info("Extension details:\n%s", output.decode())
    except psycopg2.Error as e:
        logger.error(f'Error creating extension: {e}')
        cursor.close()
        connection.close()
        raise Exception(f'Error creating extension: {e}')
    # Delete the 'events' table if it exists
    try:
        cursor.execute("DROP TABLE IF EXISTS events")
        logger.info('Table events is deleted if it exists already')
    except psycopg2.Error as e:
        logger.error(f'Error deleting table: {e}')
        cursor.close()
        connection.close()
        raise Exception(f'Error deleting table: {e}')
     # Execute the table import from S3 query
    try:
        cursor.execute("""
            CREATE TABLE events (event_id uuid primary key, event_name varchar(120) NOT NULL, event_value varchar(256) NOT NULL);
        """)

        logger.info('Events Table created successfully')

    except psycopg2.Error as e:
        logger.error(f'Error occurred while creating the table "events": {e}')
        cursor.close()
        connection.close()
        raise Exception(f'Error occurred while creating the table "events": {e}')
    # Commit the changes:Committing the changes is an essential step to ensure data integrity and durability.
    try:
        connection.commit()
        logger.info('Changes committed')
    except psycopg2.Error as e:
        logger.error(f'Error committing changes: {e}')
        cursor.close()
        connection.close()
        raise Exception(f'Error committing changes: {e}')
    # Execute the table import from S3 query
    try:
        cursor.execute(f"""
            SELECT aws_s3.table_import_from_s3(
                'events', '', '(format csv, HEADER)',
                '{s3_bucket}', '{csv_file_name}', '{region}'
            )
        """)
        logger.info("Fetching the events table data...")
        rows = cursor.fetchall()
        for row in rows:
            logger.info(row)
        logger.info(f'Data imported from S3 to table: events using the csv file {csv_file_name} in the bucket named {s3_bucket} in region {region}')
    except psycopg2.Error as e:
        logger.error(f'Error importing data from S3: {e}')
        cursor.close()
        connection.close()
        raise Exception(f'Error importing data from S3: {e}')

    # Commit the changes
    try:
        connection.commit()
        logger.info('Changes committed')
    except psycopg2.Error as e:
        logger.error(f'Error committing changes: {e}')
        cursor.close()
        connection.close()
        raise Exception(f'Error committing changes: {e}')

    # Select and print the data from the events table
    try:
        cursor.execute("SELECT * FROM events")
        rows = cursor.fetchall()
        logger.info('Data selected from table: events')
        for row in rows:
            logger.info(row)
    except psycopg2.Error as e:
        logger.error(f'Error selecting data from table: {e}')
        raise Exception(f'Error selecting data from table: {e}')

    #drop table events
    try:
        cursor.execute("DROP table events")
        logger.info('Events table was deleted from the database')
    except psycopg2.Error as e:
        logger.error(f'Error dropping the table events: {e}')
        raise Exception(f'Error dropping the table events: {e}')
        # Close the cursor and connection
    cursor.close()
    logger.info('Cursor and connection closed')


    #delete the csv file in s3 bucket
    try:
        obj = s3.Object(s3_bucket, csv_file_name)
        obj.delete()
        logger.info(f"File '{csv_file_name}' deleted successfully from bucket '{s3_bucket}'.")

    except Exception as e:
        logger.error(f"File '{csv_file_name}' does not exist in bucket '{s3_bucket}'.")
        logger.error(f"An error occurred in deleting s3 bucket dummy files: {str(e)}")
        raise Exception(f"An error occurred in deleting s3 bucket dummy files: {str(e)}")
    # delete the csv file in local
    try:
        os.remove(csv_file_name)
        logger.info(f"local file cleanup - csv file {csv_file_name} was successfully removed")
    except Exception as e:
        logger.error(f"An error occurred in removing local csv file {csv_file_name} : {str(e)}")
        raise Exception(f"An error occurred in removing local csv file {csv_file_name} : {str(e)}")


    # delete the table events
@exception_handler
def uuid_oosp_s3_extension(db_host,db_name,db_user,db_password):
  # Create a cursor
  try:

        cursor = connection.cursor()
  except psycopg2.Error as e:
        logger.error(f'Error creating a cursor: {e}')
        connection.close()
        raise Exception(f'Error creating a cursor: {e}')


  try:
        # Run the psql command to create the extension
        os.environ["PGPASSWORD"] = db_password
        #delete_extension_if_exists = f'psql -h {db_host} -d {db_name} -U {db_user} -c "DROP EXTENSION IF EXISTS \\"uuid-ossp\\";"'
        #subprocess.run(delete_extension_if_exists, shell=True, check=True)
        cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'uuid-ossp';")
        result = cursor.fetchone()
        if result is not None:
            #Extension already exists
            logger.info("Extension uuid-ossp already exists,so dropping now")
            logger.info("The RDS Sanity checks ended...")
        else:
            logger.info("uuid-ossp extension not there, creating now......")
            create_extension_cmd = f'psql -h {db_host} -d {db_name} -U {db_user} -c "CREATE EXTENSION IF NOT EXISTS \\"uuid-ossp\\";"'
            subprocess.run(create_extension_cmd, shell=True, check=True)

            logger.info("UUID-OSSP extension created successfully.")
        select_cmd = f'psql -h {db_host} -d {db_name} -U {db_user} -c "SELECT * FROM pg_extension;"'
        output = subprocess.check_output(select_cmd, shell=True)
        logger.info("Extension details:\n%s", output.decode())

  except subprocess.CalledProcessError as e:
        logger.error("Error occurred while installing UUID-OSSP extension: %s", str(e))
        raise Exception("Error occurred while creating UUID-OSSP extension: %s" % str(e))


  #delete the extension
#  try:
#        cursor = connection.cursor()

        # Check if the extension already exists
 #       cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'uuid-ossp';")
 #       result = cursor.fetchone()
#      if result is not None:
            # Extension already exists, so delete it
#            logger.info("Extension exists,so dropping now")
#            delete_extension_cmd = f'psql -h {db_host} -d {db_name} -U {db_user} -c "DROP EXTENSION IF EXISTS \\"uuid-ossp\\";"'
#            subprocess.run(delete_extension_cmd, shell=True, check=True)
#            select_cmd = f'psql -h {db_host} -d {db_name} -U {db_user} -c "SELECT * FROM pg_extension;"'
#            output = subprocess.check_output(select_cmd, shell=True)
#            logger.info("Extension details:\n%s", output.decode())
#            logger.info("UUID-OSSP extension deleted successfully")
  # Close the cursor and connection
        cursor.close()
        connection.close()

  except psycopg2.Error as e:
        logger.error("Error occurred while deleting UUID-OSSP extension: %s", str(e))
        raise Exception("Error occurred while deleting UUID-OSSP extension: %s", str(e))
@exception_handler
def check_bucket_access(s3_bucket, log_level):
    # Configure logger
    logger.info("The S3 Sanity checks started...")

    # Create an S3 client
    s3 = boto3.resource('s3')

    # Check if the bucket exists
    try:
        s3.meta.client.head_bucket(Bucket=s3_bucket)
        logger.info(f"The bucket '{s3_bucket}' exists.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            logger.error(f"The bucket '{s3_bucket}' does not exist.")
            logger.info("Please check the bucket name and ensure it exists.")
            raise Exception(f"The bucket '{s3_bucket}' does not exist: {e}")
        elif error_code == '403':
            logger.error(f"Access denied to the bucket '{s3_bucket}'.")
            logger.info("Make sure you have the necessary permissions to access the bucket.")
            raise Exception(f"Access denied to this '{s3_bucket}': {e}")
        else:
            logger.error(f"Error occurred while checking the bucket '{s3_bucket}': {e}")
            raise Exception(f"Error occurred while checking the bucket '{s3_bucket}': {e}")

    # Create a dummy file locally
    current_datetime = datetime.datetime.now(pytz.utc)
    ist_timezone = pytz.timezone('Asia/Kolkata')
    ist_datetime = datetime.datetime.now(ist_timezone)
    suffix = ist_datetime.strftime("_%Y_%m_%d_%H_%M_%S_IST")
    dummy_file_path = f"./s3-infra-sanity-check-dummy_{suffix}.txt"
    with open(dummy_file_path, 'w') as f:
        f.write('This is a dummy file used to test the read and access for the bucket from the pod.')

    # Upload the dummy file to the bucket
    bucket_location = f"s3-infra-sanity-check-dummy_{suffix}.txt"
    logger.info(f"The uploaded file name is {bucket_location}")
    try:
        s3.meta.client.upload_file(dummy_file_path, s3_bucket, bucket_location)
        logger.info(f"The dummy file was successfully uploaded to the bucket '{s3_bucket}'.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            logger.error(f"Access denied to write to the bucket '{s3_bucket}': {e}")
            logger.info("Make sure you have write access to the bucket.")
            raise Exception(f"Access denied to write to the bucket '{s3_bucket}':{e}")
        else:
            logger.error(f"Error occurred while uploading the file to the bucket '{s3_bucket}': {e}")
            raise Exception(f"Error occurred while uploading the file to the bucket '{s3_bucket}': {e}")

    # Download the dummy file from the bucket
    downloaded_file_path = f"s3-infra-sanity-check-downloaded_{suffix}.txt"
    try:
        s3.meta.client.download_file(s3_bucket, bucket_location, downloaded_file_path)
        logger.info(f"The dummy file was successfully downloaded from the bucket '{s3_bucket}'.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            logger.error(f"Access denied to read from the bucket '{s3_bucket}'.")
            logger.info("Make sure you have read access to the bucket.")
            raise Exception(f"Access denied to read from the bucket '{s3_bucket}': {e}")
        else:
            logger.error(f"Error occurred while downloading the file from the bucket '{s3_bucket}': {e}")
            raise Exception(f"Error occurred while downloading the file from the bucket '{s3_bucket}': {e}")
    # Cleanup: remove the local dummy files
    logger.info("Dummy file - locally created file which will upload it to s3 bucket")
    logger.info("Downloaded file - downloaded from the S3 bucket and it is locally available")
    try:
        os.remove(dummy_file_path)
        logger.info(f"local file cleanup - Dummy file path {dummy_file_path} was successfully removed")
    except Exception as e:
        logger.error(f"An error occurred in removing local dummy file path {dummy_file_path} : {str(e)}")
        raise Exception(f"An error occurred in removing local dummy file path {dummy_file_path} : {str(e)}")
    try:
        os.remove(downloaded_file_path)
        logger.info(f"local file cleanup - Downloaded file path {downloaded_file_path} was successfully removed")
    except Exception as e:
        logger.error(f"An error occurred in removing local downloaded file path {downloaded_file_path} : {str(e)}")
        raise Exception(f"An error occurred in removing local downloaded file path {downloaded_file_path} : {str(e)}")
    #cleanup s3 bucket dummy files
    try:
        obj = s3.Object(s3_bucket, bucket_location)
        obj.delete()
        logger.info(f"File '{bucket_location}' deleted successfully from bucket '{s3_bucket}'.")

    except Exception as e:
        logger.error(f"File '{bucket_location}' does not exist in bucket '{s3_bucket}'.")
        logger.error(f"An error occurred in deleting s3 bucket dummy files: {str(e)}")
        raise Exception(f"An error occurred in deleting s3 bucket dummy files: {str(e)}")

@exception_handler
def list_s3_buckets(log_level):
    # Create an S3 resource
    s3 = boto3.resource('s3')

    try:
        # List all buckets
        buckets = [bucket.name for bucket in s3.buckets.all()]

        # Print the name of each bucket
        for s3_bucket in buckets:
            logger.info(f"Bucket: {s3_bucket}")

        logger.info("Successfully listed all buckets. Able to access.")
        logger.info("The RDS and S3 Sanity checks were done.")
        logger.info("All is well.")

    except Exception as e:
        logger.error(f"An error occurred while trying to list the buckets: {str(e)}")
        buckets = []
        raise Exception(f"An error occurred while trying to list the buckets: {str(e)}")

    return buckets

@exception_handler
def upload_log_file_to_s3(code_execution_log_file,s3_bucket):
    bucket_location = f"infra_sanity_checks/{code_execution_log_file}"
    logger.info(f"The uploading log file name is {code_execution_log_file}")
    try:
        s3.meta.client.upload_file(code_execution_log_file, s3_bucket, bucket_location)
        logger.info(f"The log file {code_execution_log_file} was successfully uploaded to the bucket '{s3_bucket}'.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            logger.error(f"Access denied to write to the bucket '{s3_bucket}': {e}")
            logger.info("Make sure you have write access to the bucket.")
            raise Exception(f"Access denied to write to the bucket '{s3_bucket}':{e}")
        else:
            logger.error(f"Error occurred while uploading the file to the bucket '{s3_bucket}': {e}")
            raise Exception(f"Error occurred while uploading the file to the bucket '{s3_bucket}': {e}")

@exception_handler
def check_environment_variables():

    logger.info("\n")    

    logger.info("Checking environmental variables")
    
    missing = []
   # global log_level
    log_level = os.environ.get('log_level')

    if log_level:
        logger.info("Found log_level")

        logger.info("log_level = " + log_level)
    else:    
        missing.append('log_level')

   # global region
    region = os.environ.get('region')

    if region:
        logger.info("Found S3 region")

        logger.info("region = " + region)
    else:    
        missing.append('region')
        

   # global s3_bucket
    s3_bucket = os.environ.get('s3_bucket')

    if s3_bucket:

        logger.info("Found s3_bucket")
        logger.info("s3_bucket = " + s3_bucket)
        
    else:    
        missing.append('s3_bucket')



    logger.info("\n")

    
   # global csv_file_name_raw
    csv_file_name_raw = os.environ.get('csv_file_name_raw')

    if csv_file_name_raw:
        
        logger.info("Found csv_file_name_raw")
        logger.info("csv_file_name_raw = " + csv_file_name_raw)


    else:    
        missing.append('csv_file_name_raw')


        
    #global db_name
    db_name = os.environ.get('db_name')

    if db_name:
        logger.info("Found db_name")
        logger.info("db_name = " + db_name)


    else:    
        missing.append('db_name')


        
    #global db_port
    db_port = os.environ.get('db_port')

    if db_port:
        logger.info("Found db_port")
        logger.info("db_port = " + db_port)
        
    else:    
        missing.append('db_port')

    #global db_user
    db_user = os.environ.get('db_user')

    if db_user:
        logger.info("Found db_user")
        logger.info("db_user = " + db_user)

    else:
        missing.append('db_user')

    #global db_pass
    db_password = os.environ.get('db_password')

    if db_password:
        logger.info("Found db_password")
        logger.info("db_password = *****")

    else:
        missing.append('db_password')
     #   global db_host
    db_host = os.environ.get('db_host')

    if db_host:
        logger.info("Found db_host")
        logger.info("db_host = " + db_host)
        

    else:
        missing.append('db_host')
    logger.info(f"{len(missing)}")    
    if len(missing)>0:
        logger.error("The below environment Variables are missing. Cant proceed further")
        
        missing_counter = 1

        for i in missing:
            logger.info(str(missing_counter) + " . " +  i)            
            missing_counter = missing_counter + 1
            
        logger.info("Add the missing variables.")
        raise Exception("The environment Variables are missing. Cant proceed further")
    else:
       return 

@exception_handler
def local_log_file_cleanup(code_execution_log_file):
    try:
        os.remove(code_execution_log_file)
        logger.info(f"local file cleanup - log file {code_execution_log_file} was successfully removed")
    except Exception as e:
        logger.error(f"An error occurred in removing local log file path {code_execution_log_file} : {str(e)}")
        raise Exception(f"An error occurred in removing local log file path {code_execution_log_file} : {str(e)}")
logger.info("The RDS Sanity checks started...")
if check_special_characters(db_password):
    logger.error("Password contains special characters.")
    raise Exception("Password contains special characters.")
else:
    logger.info("Password does not contains any special characters.")

    

check_environment_variables()
upload_csv_to_s3(csv_file_name,s3_bucket)
check_rds_access(db_host, db_port, db_user, db_password, db_name, log_level)
import_data_from_s3()
uuid_oosp_s3_extension(db_host,db_user,db_name,db_password)
check_bucket_access(s3_bucket, log_level)
list_s3_buckets(log_level)
upload_log_file_to_s3(code_execution_log_file,s3_bucket)
local_log_file_cleanup(code_execution_log_file)
#logger.info("exiting with 0")
#exit_command = "exit 0"
#subprocess.check_output(exit_command, shell=True)
logger.info("sleep mode")
sleep_cmd = "/bin/sleep 3650d"
subprocess.check_output(sleep_cmd, shell=True)
