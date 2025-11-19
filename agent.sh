#!/bin/env bash
while [ true ]; do
  sleep 30
  /bin/bash /opt/scripts/saslnotif/sasl_combined.sh
  date
done
