FROM python:3.9.5

COPY litrack_api.py /api

COPY __init__.py /api

COPY prod_model.h5 /model

COPY requirements.txt requirements.txt

RUN pip install -r /requirements.txt

WORKDIR /api

ENV PYTHONUNBUFFERED=1

ENV JWT_SECRET_KEY="super-secret"

ENV MAIL_USERNAME="litter.tracker.project@gmail.com"

ENV MAIL_PASSWORD="derswvpaomaxnfyy"

ENV DB_USER="docker"

ENV DB_PWD="docker"

EXPOSE 5000

#CMD python ./api/litrack_api.py

CMD ["python3", "-m", "gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--certfile", "/etc/letsencrypt/live/litter-tracker.eu/fullchain.pem", "--keyfile", "/etc/letsencrypt/live/litter-tracker.eu/privkey.pem", "litrack_api:app"]