#!/bin/sh -efu

# load settings
if [ ! -f .prefix ]; then
    echo 'Run prepare.sh first.' >&2
    exit 1
fi
PREFIX=$(cat .prefix)

# grant access to lambda functions
aws iam put-role-policy \
    --role-name "${PREFIX}-function-role" \
    --policy-name RekognitionAccessPolicy \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rekognition:DetectText","Resource":"*"}]}'
