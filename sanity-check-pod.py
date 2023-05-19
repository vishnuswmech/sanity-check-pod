import subprocess
import logging
import re
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command):
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode('utf-8'), error.decode('utf-8'), process.returncode

def check_s3_bucket(bucket_name):
    # Check if the bucket exists
    command = f"aws s3api head-bucket --bucket {bucket_name}"
    output, error, returncode = run_command(command)
    print(f"output is '{output}' and error is '{error}' and returncode is '{returncode}'")
    print(type(error))
    errorcode = re.findall(r'\d+', error)
    print(int(errorcode))
    if returncode == 0:
        logging.info(f"S3 bucket '{bucket_name}' exists.")
    else:
        logging.error(f"S3 bucket '{bucket_name}' does not exist. Error: {error.strip()}")

    # Additional checks can be added here

if __name__ == "__main__":
    # Replace 'your_bucket_name' with your S3 bucket name
    bucket_name = 'your_bucket_name'

    check_s3_bucket("vishnu-test12345")
