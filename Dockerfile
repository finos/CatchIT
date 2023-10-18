FROM python:3.8-slim

RUN mkdir /app

COPY . /app

WORKDIR /app

ENV PYTHONPATH=${PYTHONPATH}:${PWD} 

RUN pip3 install poetry

RUN poetry config virtualenvs.create false

RUN poetry install --no-dev

ENTRYPOINT ["python3", "/app/catchit/catchit.py", "--scan-path"]