#!/bin/sh -efu

# prerequisites
sudo apt-get install unzip
if ! which aws > /dev/null; then
    echo 'Installing AWS CLI...'
    TEMPDIR=$(mktemp --directory)
    curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' --output "${TEMPDIR}/awscliv2.zip"
    unzip -d "${TEMPDIR}" "${TEMPDIR}/awscliv2.zip"
    sudo "${TEMPDIR}/aws/install"
    rm --force --recursive "${TEMPDIR}"
    aws configure
fi

# query user
RANDOM_PREFIX="project-$(cat /dev/urandom | tr --delete --complement '[:digit:]' | fold --width=6 | head --lines=1)"
read -p "Prefix [${RANDOM_PREFIX}]: " PREFIX
if [ -z "${PREFIX}" ]; then
    PREFIX="${RANDOM_PREFIX}"
fi
RANDOM_KEY=$(cat /dev/urandom | tr --delete --complement '[:alnum:]' | fold --width=20 | head --lines=1)
read -p "Function Key [${RANDOM_KEY}]: " KEY
if [ -z "${KEY}" ]; then
    KEY="${RANDOM_KEY}"
fi

# store settings
echo -n "${PREFIX}" > .prefix
echo -n "${KEY}" > .key
mkdir --parents .lambda-urls

# build infrastructure
set -x
ROLE_ARN=$(aws iam create-role \
    --role-name "${PREFIX}-function-role" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    --query Role.Arn \
    --output text \
)
aws iam attach-role-policy \
    --role-name "${PREFIX}-function-role" \
    --policy-arn 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
aws iam put-role-policy \
    --role-name "${PREFIX}-function-role" \
    --policy-name S3AccessPolicy \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket","s3:PutObject","s3:GetObject","s3:DeleteObject"],"Resource":"*"}]}'
sleep 5
rm --force .function.zip
(
    cd function
    npm install
    zip -r -9 ../.function.zip .
)
for REGION in $(cat regions.txt); do
    aws lambda create-function \
        --region "${REGION}" \
        --function-name "${PREFIX}-function" \
        --role "${ROLE_ARN}" \
        --runtime nodejs18.x \
        --zip-file fileb://.function.zip \
        --handler index.handler \
        --environment "{\"Variables\":{\"REGION\": \"${REGION}\", \"BUCKET\": \"${PREFIX}-${REGION}\", \"HMAC_KEY\": \"${KEY}\"}}" \
        --memory-size 256 \
        --timeout 120 \
        --query FunctionArn \
        --output text
    aws lambda create-function-url-config \
        --region "${REGION}" \
        --function-name "${PREFIX}-function" \
        --auth-type NONE \
        --query FunctionUrl \
        --output text \
        > ".lambda-urls/${REGION}"
    aws lambda add-permission \
        --region "${REGION}" \
        --function-name "${PREFIX}-function" \
        --statement-id FunctionURLAllowPublicAccess \
        --action lambda:InvokeFunctionUrl \
        --principal '*' \
        --function-url-auth-type NONE \
        --query Statement.Resource \
        --output text
    if [ "${REGION}" = 'us-east-1' ]; then
        BUCKET_CONFIG=''
    else
        BUCKET_CONFIG="--create-bucket-configuration LocationConstraint=${REGION}"
    fi
    aws s3api create-bucket \
        --region "${REGION}" \
        --bucket "${PREFIX}-${REGION}" \
        ${BUCKET_CONFIG} \
        --query Location \
        --output text
    aws s3api put-bucket-policy \
        --region "${REGION}" \
        --bucket "${PREFIX}-${REGION}" \
        --policy "{ \"Version\": \"2012-10-17\", \"Statement\": { \"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::${PREFIX}-${REGION}/*\" } }"
done
