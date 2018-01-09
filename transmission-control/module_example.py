import os
import logging

from TransmissionControl import *

rootLogger = logging.getLogger()
rootLogger.setLevel(logging.INFO)

stdout_logger = logging.StreamHandler(sys.stdout)
stdout_logger.setLevel(logging.DEBUG)
stdout_logger_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stdout_logger.setFormatter(stdout_logger_formatter)
rootLogger.addHandler(stdout_logger)

tcontrol = TransmissionControl()

tconfiguration = {
    "dry_run": False,
    "verbose": True,
    "silent": False,
    "host_address": "192.168.1.1",
    "host_port": 9091,
    "username": "transmission",
    "password": "password",
    "move_rules": {
        "(.*)pdf$": '/smb/ebooks',
        "(.*)demos$": '/smb/torrents/complete/demos',
    },
    "suppress_move_warnings": True,
}

logging.info(tcontrol.name + " started")

try:
    tcontrol.run(tconfiguration)
except Exception as e:
    logging.exception(e)
    sys.exit(1)

logging.info(tcontrol.name + " finished")
