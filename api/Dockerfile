FROM python:3.9.5

COPY . /api

COPY requirements.txt requirements.txt

RUN pip install -r /requirements.txt

ENV PYTHONUNBUFFERED=1

ENV JWT_SECRET_KEY="SECRET PASSWORD TO MODIFY"

ENV MAIL_USERNAME="litter.tracker.project@gmail.com"

ENV MAIL_PASSWORD="GMAIL TOKEN TO MODIFY"

ENV DB_USER="docker"

ENV DB_PWD="docker"

CMD python ./api/litrack_api.py