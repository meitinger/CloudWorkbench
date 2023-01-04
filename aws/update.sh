#!/bin/sh -efu

# load settings
PREFIX=$(cat .prefix)
KEY=$(cat .key)

# update functions
set -x
ROLE_ARN=$(aws iam get-role \
    --role-name "${PREFIX}-function-role" \
    --query Role.Arn \
    --output text \
)
rm --force .function.zip
(
    cd function
    npm install
    zip -r -9 ../.function.zip .
)
for REGION in $(cat regions.txt); do
    aws lambda update-function-configuration \
        --region "${REGION}" \
        --function-name "${PREFIX}-function" \
        --role "${ROLE_ARN}" \
        --runtime nodejs18.x \
        --handler index.handler \
        --environment "{\"Variables\":{\"REGION\": \"${REGION}\", \"BUCKET\": \"${PREFIX}-${REGION}\", \"HMAC_KEY\": \"${KEY}\"}}" \
        --memory-size 256 \
        --timeout 120 \
        --query FunctionArn \
        --output text
    aws lambda update-function-code \
        --region "${REGION}" \
        --function-name "${PREFIX}-function" \
        --zip-file fileb://.function.zip \
        --query CodeSha256 \
        --output text
done
