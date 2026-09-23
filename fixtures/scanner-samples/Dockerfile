FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD app.tar.gz /app
EXPOSE 22
CMD ["python", "app.py"]
