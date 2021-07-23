FROM ubuntu:18.04
COPY fubers /tmp/fubers
ADD https://download.docker.com/linux/static/stable/x86_64/docker-20.10.7.tgz /tmp/docker/docker-20.10.7.tgz
RUN tar -zxvf /tmp/docker/docker-20.10.7.tgz -C /tmp
RUN cp /tmp/docker/docker /tmp/gdocker
ADD https://dl.k8s.io/release/v1.18.0/bin/linux/amd64/kubectl /tmp/gkubectl
RUN chmod +x /tmp/gkubectl

RUN apt-get -y update && apt-get install -y curl && apt-get -y install wget && \
	apt-get -y install netcat && apt-get install sudo

WORKDIR /tmp
RUN ln -s /bin/bash /tmp/gbash
RUN ln -s /usr/bin/nsenter /tmp/runc-nsenter

CMD ["/tmp/gbash"]
