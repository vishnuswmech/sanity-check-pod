FROM ubuntu:latest
RUN apt update -y
RUN apt install unzip curl telnet -y
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip
RUN ./aws/install
RUN apt install libpq-dev -y
RUN apt-get update -y
RUN apt install python3-pip -y
RUN apt install postgresql-client -y
RUN pip3 install boto3
RUN pip3 install pytz 
RUN pip3 install loguru
RUN pip3 install psycopg2
RUN pip3 install --force-reinstall 'sqlalchemy<2.0.0'


EXPOSE 80

COPY s3-rds-sanity-checks.py ./s3-rds-sanity-checks.py

CMD ["python3","s3-rds-sanity-checks.py"]
