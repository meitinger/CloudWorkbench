#!/bin/sh -efu

# prerequisites
if ! which az > /dev/null || ! which func > /dev/null; then
    echo 'Installing Azure CLI and Function Core Tools...'
    curl --silent https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor \
        | sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
    sudo tee /etc/apt/sources.list.d/microsoft.list > /dev/null << EOF
deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main
deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-$(lsb_release -cs)-prod $(lsb_release -cs) main
EOF
    sudo apt-get update
    sudo apt-get install azure-cli azure-functions-core-tools-4
    az login
fi

# query user
RANDOM_GROUP=rg$(cat /dev/urandom | tr --delete --complement 'a-z0-9' | fold --width=4 | head --lines=1)
read -p "Resource Group [${RANDOM_GROUP}]: " GROUP
if [ -z "${GROUP}" ]; then
    GROUP="${RANDOM_GROUP}"
fi
RANDOM_KEY=$(cat /dev/urandom | tr --delete --complement '[:alnum:]' | fold --width=20 | head --lines=1)
read -p "Function Key [${RANDOM_KEY}]: " KEY
if [ -z "${KEY}" ]; then
    KEY="${RANDOM_KEY}"
fi
read -p "Container Name [files]: " CONTAINER
if [ -z "${CONTAINER}" ]; then
    CONTAINER=files
fi
read -p "Primary Location [germanywestcentral]: " PRIMARY_LOCATION
if [ -z "${PRIMARY_LOCATION}" ]; then
    PRIMARY_LOCATION=germanywestcentral
fi

# store settings
echo -n "${GROUP}" > .group
echo -n "${KEY}" > .key
echo -n "${CONTAINER}" > .container

# build infrastructure
set -x
TENANT_ID=$(az account show --query tenantId --output tsv)
az group create --location "${PRIMARY_LOCATION}" --resource-group "${GROUP}" --output none
IDENTITY_ID=$(az identity create \
    --name "${GROUP}-function-identity" \
    --resource-group "${GROUP}" \
    --location "${PRIMARY_LOCATION}" \
    --query id \
    --output tsv \
)
PRINCIPAL_ID=$(az identity show \
    --ids "${IDENTITY_ID}" \
    --query principalId \
    --output tsv \
)
CLIENT_ID=$(az identity show \
    --ids "${IDENTITY_ID}" \
    --query clientId \
    --output tsv \
)
az role assignment create \
    --role 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' \
    --assignee-object-id "${PRINCIPAL_ID}" \
    --assignee-principal-type ServicePrincipal \
    --output none
for REGION in $(cat regions.txt); do
    az storage account create \
        --name "${GROUP}${REGION}" \
        --resource-group "${GROUP}" \
        --location "${REGION}" \
        --sku Standard_LRS \
        --output none
    az storage container create \
        --name "${CONTAINER}" \
        --account-name "${GROUP}${REGION}" \
        --auth-mode key \
        --public-access blob \
        --output none
    az functionapp create \
        --name "${GROUP}-${REGION}-function" \
        --resource-group "${GROUP}" \
        --storage-account "${GROUP}${REGION}" \
        --assign-identity "${IDENTITY_ID}" \
        --consumption-plan-location "${REGION}" \
        --disable-app-insights true \
        --functions-version 4 \
        --os-type Linux \
        --runtime node \
        --runtime-version 18 \
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
