FROM alpine:edge

RUN apk --update add --no-cache python3 py3-requests py3-pip openssl ca-certificates
RUN apk --update add --virtual build-dependencies python3-dev build-base
RUN mkdir /trevorc2
COPY requirements.txt /trevorc2/
RUN pip3 install -r /trevorc2/requirements.txt
COPY . /trevorc2/
WORKDIR /trevorc2
EXPOSE 80 443
ENTRYPOINT ["python3", "trevorc2_server.py"]

