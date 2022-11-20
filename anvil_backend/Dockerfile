FROM python:3.9.5

COPY . /app

COPY requirements.txt requirements.txt

RUN pip install -r /requirements.txt

ENV PYTHONUNBUFFERED=1

ENV ANVIL_SERVER="ANVIL TOKEN TO MODIFY"

CMD python ./app/AnvilServer.py