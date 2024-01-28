FROM ubuntu:22.04
MAINTAINER g00fb4ll <sshayb@gmail.com>
COPY fubers /tmp/fubers
ADD https://download.docker.com/linux/static/stable/x86_64/docker-24.0.8.tgz /tmp/docker/docker-24.0.8.tgz
RUN tar -zxvf /tmp/docker/docker-24.0.8.tgz -C /tmp
RUN cp /tmp/docker/docker /tmp/gdocker
ADD https://dl.k8s.io/release/v1.27.0/bin/linux/amd64/kubectl /tmp/gkubectl
RUN chmod +x /tmp/gkubectl
ADD https://github.com/cyberark/kubeletctl/releases/download/v1.11/kubeletctl_linux_amd64 /tmp/kubeletctl
RUN chmod a+x /tmp/kubeletctl

RUN apt-get -y update
RUN apt-get install -y curl
RUN apt-get -y install wget && \
        apt-get -y install netcat && apt-get install sudo && apt-get -y install redis-tools && \
        apt-get -y install netdiscover && apt-get install tcpdump

WORKDIR /tmp
RUN ln -s /bin/bash /tmp/gbash
RUN ln -s /usr/bin/nsenter /tmp/runc-nsenter

CMD ["/tmp/gbash"]
