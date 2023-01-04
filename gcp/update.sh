#!/bin/sh -efu

# load settings
PROJECT=$(cat .project)
KEY=$(cat .key)

# update functions
set -x
for REGION in $(cat regions.txt); do
    gcloud functions deploy 'function' \
        --region="${REGION}" \
        --source=./function \
        --allow-unauthenticated \
        --runtime=nodejs18 \
        --trigger-http \
        --entry-point=run \
        --set-env-vars="REGION=${REGION},BUCKET=${PROJECT}-${REGION},HMAC_KEY=${KEY}" \
        --memory=256MB \
        --timeout=120s \
        --project="${PROJECT}" \
        --format none
done
