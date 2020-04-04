FROM debian:buster-slim

MAINTAINER Zane Claes <zane@technicallywizardry.com>

USER root

RUN apt-get clean -y && apt-get update -y && \
    apt-get install --no-install-recommends -y python3-pip python3-setuptools && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip3 install argparse prometheus_client

RUN apt-get update -y && apt-get install -y tcpdump

COPY services /etc/services
COPY network-traffic-metrics.py /usr/bin/network-traffic-metrics.py
RUN chmod +x /usr/bin/network-traffic-metrics.py
CMD /usr/bin/network-traffic-metrics.py

EXPOSE 8000
