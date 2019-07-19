FROM buildpack-deps:stretch

RUN echo 'deb http://deb.nodesource.com/node_8.x artful main' > /etc/apt/sources.list.d/nodesource.list

RUN curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add -
RUN apt-get update && \
    apt-get install --yes nodejs python3 python3-pip python3-wheel python3-setuptools

COPY . /tmp/binderhub
WORKDIR /tmp/binderhub

RUN python3 setup.py bdist_wheel

FROM python:3.6-stretch

COPY --from=0 /tmp/binderhub/dist/*.whl .
ADD helm-chart/images/binderhub/binderhub_config.py .
ADD helm-chart/images/binderhub/requirements.txt /tmp/requirements.txt
ADD GeoTrust_RSA_CA_2018.crt   /usr/local/share/ca-certificates
ADD gitlab.crt    /usr/local/share/ca-certificates
RUN pip install --no-cache-dir *.whl -r /tmp/requirements.txt  && \
    update-ca-certificates --fresh && \
openssl s_client -showcerts -connect gitlab.bnu.edu.cn:443 2>/dev/null  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'  >> /etc/ssl/certs/ca-certificates.crt

CMD ["python3", "-m", "binderhub"]
ENV PYTHONUNBUFFERED=1
EXPOSE 8585
