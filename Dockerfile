FROM python:3.12-slim-bookworm
COPY . /opt/offlist
WORKDIR /opt/offlist
RUN pip install --no-cache-dir .
ENTRYPOINT ["offlist"]
CMD ["--help"]
