FROM python:3.8

RUN useradd -m -U app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /home/app
USER app

COPY server.py server.py

ENV PYTHONPATH=/home/app

CMD ["python", "server.py"]
