#!/bin/sh
cd /opt/transmission-control
/usr/bin/env python TransmissionControl.py -w password -r my_move.rules 2>&1 >> /var/log/transmission-control.log
