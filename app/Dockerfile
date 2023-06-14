FROM python:3.10.12

EXPOSE 5000

WORKDIR /app

COPY requirements.txt /app/
COPY templates /app/
RUN pip install -r requirements.txt

CMD python app.py
