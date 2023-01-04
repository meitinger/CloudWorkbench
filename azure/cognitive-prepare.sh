#!/bin/sh -efu

# load settings
if [ ! -f .group ]; then
    echo 'Run prepare.sh first.' >&2
    exit 1
fi
GROUP=$(cat .group)
mkdir --parents .cognitive-keys

# create accounts
set -x
for REGION in $(cat cognitive-regions.txt); do
    az cognitiveservices account create \
        --kind ComputerVision \
        --location "${REGION}" \
        --name "${GROUP}-${REGION}-computervision" \
        --resource-group "${GROUP}" \
        --sku F0 \
        --output none
    az cognitiveservices account keys list \
        --name "${GROUP}-${REGION}-computervision" \
        --resource-group "${GROUP}" \
        --query key1 \
        --output tsv \
        > ".cognitive-keys/${REGION}"
done
