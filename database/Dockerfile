FROM postgres:latest

COPY ./resources ./resources

ENV POSTGRES_PASSWORD=docker

ENV POSTGRES_USER=docker

ENV POSTGRES_DB=LITRACK

COPY create_fixtures.sql /docker-entrypoint-initdb.d/create_fixtures.sql
