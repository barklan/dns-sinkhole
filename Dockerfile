FROM python:3.10.1-slim as builder

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc

COPY requirements.txt .
RUN pip install --no-cache wheel && pip install --no-cache -r requirements.txt

WORKDIR /home/ubuntu

RUN mkdir -p /home/ubuntu/unbound

COPY . .

ENTRYPOINT ["bash", "-c", "python3 dns-sinkhole-gen.py"]
