FROM python:3.9.5

COPY . /app

COPY requirements.txt requirements.txt

RUN pip install -r /requirements.txt

ENV PYTHONUNBUFFERED=1

ENV ANVIL_SERVER="server_4GVEPMPDKB3K4G4E4V67XBSH-CNQ5K24RHGWGHDTE"

CMD python ./app/AnvilServer.py