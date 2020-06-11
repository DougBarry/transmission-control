FROM python:3

ENV TCONTROL_ARGS=""
ENV TCONTROL_RULES_FILE="/transmission-control/rules/default_rules.json"
ENV TCONTROL_TRACKERS_LIST="/transmission-control/trackers/default_trackers.list"
ENV TRANSMISSION_HOST=""
ENV TRANSMISSION_PORT=""
ENV TRANSMISSION_USERNAME=""
ENV TRANSMISSION_PASSWORD=""

COPY transmission-control /transmission-control/
COPY transmission-control/moverules_example.json /transmission-control/rules/default_rules.json
COPY transmission-control/default_trackers_examples.list /transmission-control/trackers/default_trackers.list

RUN pip install transmissionrpc

RUN echo -e \n >> /empty_trackers.list

CMD [ "python", "/transmission-control/TransmissionControl.py", "${TCONTROL_ARGS} -t ${TRANSMISSION_HOST} -p ${TRANSMISSION_PORT} -u ${TRANSMISSION_USERNAME} -w ${TRANSMISSION_PASSWORD} -r ${TCONTROL_RULES_FILE} -a ${TCONTROL_TRACKERS_LIST}]
