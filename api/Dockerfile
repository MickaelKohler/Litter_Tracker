FROM python:3.9.5

COPY litrack_api.py /api

COPY prod_model.h5 /model

COPY requirements.txt requirements.txt

RUN pip install -r /requirements.txt

ENV PYTHONUNBUFFERED=1

ENV JWT_SECRET_KEY="super-secret"

ENV MAIL_USERNAME="litter.tracker.project@gmail.com"

ENV MAIL_PASSWORD="derswvpaomaxnfyy"

ENV DB_USER="docker"

ENV DB_PWD="docker"

CMD python ./api/litrack_api.py