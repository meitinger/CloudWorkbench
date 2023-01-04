#!/bin/sh -efu

# load settings
GROUP=$(cat .group)
KEY=$(cat .key)
CONTAINER=$(cat .container)

# update functions
set -x
TENANT_ID=$(az account show --query tenantId --output tsv)
IDENTITY_ID=$(az identity show \
    --name "${GROUP}-function-identity" \
    --resource-group "${GROUP}" \
    --query id \
    --output tsv \
)
CLIENT_ID=$(az identity show \
    --ids "${IDENTITY_ID}" \
    --query clientId \
    --output tsv \
)
for REGION in $(cat regions.txt); do
    az functionapp identity assign \
        --name "${GROUP}-${REGION}-function" \
        --resource-group "${GROUP}" \
        --identities "${IDENTITY_ID}" \
        --output none
    az functionapp config appsettings set \
        --name "${GROUP}-${REGION}-function" \
        --resource-group "${GROUP}" \
        --settings \
            "AZURE_CLIENT_ID=${CLIENT_ID}" \
            "AZURE_TENANT_ID=${TENANT_ID}" \
            "REGION=${REGION}" \
            "RESOUCE_GROUP=${GROUP}" \
            "STORAGE_ACCOUNT=${GROUP}${REGION}" \
            "CONTAINER=${CONTAINER}" \
            "HMAC_KEY=${KEY}" \
        --output none
done
(
    cd ./function
    npm install
    for REGION in $(cat ../regions.txt); do
        func azure functionapp publish "${GROUP}-${REGION}-function"
    done
)
