#!/bin/bash
if [ $# -eq 0 ]
  then
    echo "No arguments supplied. Please supply the environment (local or dev)"
    exit 1
fi
environment=$1
if [ "$environment" == "local" ]; then
  docker-compose -f docker-compose.yml -f docker-compose.local.yml up -d
elif [ "$environment" == "dev" ]; then
  docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
else
  echo "Invalid environment specified ($1)"
fi
