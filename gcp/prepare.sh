#!/bin/sh -efu

# prerequisites
if ! which gcloud > /dev/null; then
    echo 'Installing Google Cloud CLI...'
    curl 'https://sdk.cloud.google.com' | bash
    exec -l ${SHELL}
    gcloud init
    gcloud components install beta
fi

# fetch all billing accounts
ACCOUNTS=$(gcloud beta billing accounts list --format 'csv(name,displayName)' | tail --lines=+2)
ACCOUNTS_COUNT=$(echo "${ACCOUNTS}" | wc --lines)
if [ "${ACCOUNTS_COUNT}" -eq 0 ]; then
    echo 'No billing accounts available.' >&2
    exit 1
fi

# query user
RANDOM_PROJECT="project-$(cat /dev/urandom | tr --delete --complement '[:digit:]' | fold --width=6 | head --lines=1)"
read -p "Project ID [${RANDOM_PROJECT}]: " PROJECT
if [ -z "${PROJECT}" ]; then
    PROJECT="${RANDOM_PROJECT}"
fi
RANDOM_KEY=$(cat /dev/urandom | tr --delete --complement '[:alnum:]' | fold --width=20 | head --lines=1)
read -p "Function Key [${RANDOM_KEY}]: " KEY
if [ -z "${KEY}" ]; then
    KEY="${RANDOM_KEY}"
fi
echo 'Choose a billing account:'
echo "${ACCOUNTS}" | awk -F ',' '{print NR ". " $2 " (" $1 ")"}'
ACCOUNT_INDEX=0
until [ "${ACCOUNT_INDEX}" -ge 1 ] && [ "${ACCOUNT_INDEX}" -le "${ACCOUNTS_COUNT}" ]; do
    read -p ': ' ACCOUNT_INDEX
done
ACCOUNT=$(echo "${ACCOUNTS}" | awk -F ',' "{if(NR==${ACCOUNT_INDEX}){print \$1}}")

# store settings
echo -n "${PROJECT}" > .project
echo -n "${KEY}" > .key

# build infrastructure
set -x
gcloud projects create "${PROJECT}" --format none
gcloud beta billing projects link "${PROJECT}" --billing-account="${ACCOUNT}" --format none
gcloud services enable --project="${PROJECT}" --format none \
    cloudfunctions.googleapis.com \
    cloudbuild.googleapis.com
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
    gcloud storage buckets create "gs://${PROJECT}-${REGION}" \
        --default-storage-class=STANDARD \
        --location="${REGION}" \
        --project="${PROJECT}" \
        --format none
    gsutil iam ch "serviceAccount:${PROJECT}@appspot.gserviceaccount.com:objectCreator" "gs://${PROJECT}-${REGION}"
    gsutil iam ch "serviceAccount:${PROJECT}@appspot.gserviceaccount.com:objectViewer" "gs://${PROJECT}-${REGION}"
    gsutil iam ch 'allUsers:objectViewer' "gs://${PROJECT}-${REGION}"
done
