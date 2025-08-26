FROM python:3.6

EXPOSE 5000

WORKDIR /app

RUN apt-get update && apt-get install -y default-libmysqlclient-dev build-essential

COPY requirements.txt /app/
COPY templates /app/
COPY src /app/src
RUN pip install -r requirements.txt

CMD python app.py
