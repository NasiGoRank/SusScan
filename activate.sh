#!/usr/bin/env bash
source "/opt/SusScan/venv/bin/activate"
export SUSSCAN_HOME="/opt/SusScan"
export PATH="/opt/SusScan/venv/bin:$PATH"
if [[ -f "/opt/SusScan/.env" ]]; then
  set -a
  source "/opt/SusScan/.env"
  set +a
elif [[ -f "/opt/SusScan/app/.env" ]]; then
  set -a
  source "/opt/SusScan/app/.env"
  set +a
fi
