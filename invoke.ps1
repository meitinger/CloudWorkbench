# Copyright (C) 2023, Manuel Meitinger
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

Set-StrictMode -Version Latest
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop


# Load Regions

$Providers = @('AWS','Azure','GCP')
$Regions = @{}
$Providers.ForEach({
    $Regions[$_] = Get-Content -LiteralPath "$PSScriptRoot/$_/regions.txt" -Encoding utf8
})
$All = $Providers.ForEach({
    Param ($Provider=$_)
    $Regions[$Provider].ForEach({New-Object -TypeName PSObject -Property @{
        Provider=$Provider
        Region=$_
    }})
})
$OcrRegions = @{
    AWS=Get-Content -LiteralPath "$PSScriptRoot/aws/rekognition-regions.txt" -Encoding utf8
    Azure=Get-Content -LiteralPath "$PSScriptRoot/azure/cognitive-regions.txt" -Encoding utf8
    GCP=$Regions['GCP']
}
$OcrAll = $Providers.ForEach({
    Param ($Provider=$_)
    $OcrRegions[$Provider].ForEach({New-Object -TypeName PSObject -Property @{
        Provider=$Provider
        Region=$_
    }})
})


# Google Cloud Platform

$GCP = $All.Where({ $_.Provider -eq 'GCP' })
$GCP_Project = Get-Content -LiteralPath "$PSScriptRoot/gcp/.project" -Encoding utf8
$GCP_StorageBucket =`
"((function () {
  const { Storage } = require('@google-cloud/storage')
  return new Storage().bucket(process.env.BUCKET)
})())"
$GCP_Ocr = `
"(async function (fileName) {
  const imageUri = ``https://storage.googleapis.com/`${process.env.BUCKET}/`${fileName}``
  const { GoogleAuth } = require('google-auth-library')
  const auth = new GoogleAuth({ scopes: 'https://www.googleapis.com/auth/cloud-platform' })
  const token = await auth.getAccessToken()
  const body = {
    requests: {
      image: { source: { imageUri } },
      features: { type: 'TEXT_DETECTION' }
    }
  }
  const options = {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token },
    body: JSON.stringify(body)
  }
  return { uri: 'https://vision.googleapis.com/v1/images:annotate', options }
})"


# Microsoft Azure

$Azure = $All.Where({ $_.Provider -eq 'Azure' })
$Azure_Group = Get-Content -LiteralPath "$PSScriptRoot/azure/.group" -Encoding utf8
$Azure_Container = Get-Content -LiteralPath "$PSScriptRoot/azure/.container" -Encoding utf8
$Azure_CognitiveKeys = @{}
$OcrRegions['Azure'].ForEach({
    $Azure_CognitiveKeys[$_] = Get-Content -LiteralPath "$PSScriptRoot/azure/.cognitive-keys/$_" -Encoding utf8
})
$Azure_ContainerClient =`
"((function () {
  const { BlobServiceClient } = require('@azure/storage-blob')
  const { ManagedIdentityCredential } = require('@azure/identity')
  const blobServiceClient = new BlobServiceClient(
    ``https://`${process.env.STORAGE_ACCOUNT}.blob.core.windows.net``,
    new ManagedIdentityCredential(process.env.AZURE_CLIENT_ID)
  )
  return blobServiceClient.getContainerClient(process.env.CONTAINER)
})())"
$Azure_Ocr = `
"(async function (fileName, subscriptionKey) {
  const url = ``https://`${process.env.STORAGE_ACCOUNT}.blob.core.windows.net/`${process.env.CONTAINER}/`${fileName}``
  const options = {
    method: 'POST',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json',
      'Ocp-Apim-Subscription-Key': subscriptionKey
    },
    body: JSON.stringify({ url })
  }
  return { uri: ``https://`${process.env.REGION}.api.cognitive.microsoft.com/vision/v3.2/ocr``, options }
})"


# Amazon Web Services

$AWS = $All.Where({ $_.Provider -eq 'AWS' })
$AWS_Prefix = Get-Content -LiteralPath "$PSScriptRoot/aws/.prefix" -Encoding utf8
$AWS_LambdaUrls = @{}
$Regions['AWS'].ForEach({
    $AWS_LambdaUrls[$_] = Get-Content -LiteralPath "$PSScriptRoot/aws/.lambda-urls/$_" -Encoding utf8
})
$AWS_S3 =`
"((function () {
  const AWS = require('aws-sdk')
  return new AWS.S3()
})())"
$AWS_Bucket = "{ Bucket: process.env.BUCKET }"
$AWS_Ocr = `
"(async function (fileName) {
  const { createHash, createHmac } = await import('node:crypto')
  const method = 'POST'
  const host = ``rekognition.`${process.env.REGION}.amazonaws.com``
  const target = 'RekognitionService.DetectText'
  const body = JSON.stringify({ Image: { S3Object: { ...$AWS_Bucket, Name: fileName } } })
  const bodyHash = createHash('sha256').update(body).digest('hex')
  const dateIso = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '')
  const datePart = dateIso.substr(0, 8)
  const service = 'rekognition'
  const v4Identifier = 'aws4_request'
  const credentialString = ```${datePart}/`${process.env.REGION}/`${service}/`${v4Identifier}``
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target'
  const algorithm = 'AWS4-HMAC-SHA256'
  const canonicalString = [
    method,
    '/',
    '',
    'host:' + host,
    'x-amz-content-sha256:' + bodyHash,
    'x-amz-date:' + dateIso,
    'x-amz-security-token:' + process.env.AWS_SESSION_TOKEN,
    'x-amz-target:' + target,
    '',
    signedHeaders,
    bodyHash
  ].join('\n')
  const stringToSign = [
    algorithm,
    dateIso,
    credentialString,
    createHash('sha256').update(canonicalString).digest('hex')
  ].join('\n')
  const kDate = createHmac('sha256', 'AWS4' + process.env.AWS_SECRET_ACCESS_KEY).update(datePart).digest()
  const kRegion = createHmac('sha256', kDate).update(process.env.REGION).digest()
  const kService = createHmac('sha256', kRegion).update(service).digest()
  const kSigning = createHmac('sha256', kService).update(v4Identifier).digest()
  const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex')
  const options = {
    method,
    headers: {
      'Authorization': ```${algorithm} Credential=`${process.env.AWS_ACCESS_KEY_ID}/`${credentialString}, SignedHeaders=`${signedHeaders}, Signature=`${signature}``,
      'Content-Type': 'application/x-amz-json-1.1',
      'Host': host,
      'X-Amz-Content-Sha256':bodyHash,
      'X-Amz-Date': dateIso,
      'X-Amz-Security-Token': process.env.AWS_SESSION_TOKEN,
      'X-Amz-Target': target
    },
    body
  }
  return { uri: ``https://`${host}/``, options }
})"



# Functions and Filters


Function ConvertTo-ExecCommand {
    Param (
        [Parameter(Mandatory=$true)]
        [string] $Command
    )

"const { exec } = await import('node:child_process')
return await new Promise((resolve, reject) => {
  exec($(ConvertTo-Json $Command), (error, stdout, stderr) => {
    if (error) {
      reject(error)
    }
    else {
      resolve(stdout)
    }
  })
})"
}


Filter Invoke-CloudFunction {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    ,
        [Parameter(Mandatory=$true)]
        [string] $Command
    ,
        [switch] $Raw
    )

    If ($Region -notin $Regions[$Provider]) { Throw "Unknown region '$Region', supported are $($Regions[$Provider] -join ', ')." }
    $location = $Region.ToLowerInvariant()
    $url = Switch ($Provider) {
        'GCP' { "https://$location-$GCP_Project.cloudfunctions.net/function" }
        'AWS' { $AWS_LambdaUrls[$Region] }
        'Azure' { "https://$Azure_Group-$location-function.azurewebsites.net/api/v1" }
        Default { Throw [System.NotImplementedException]::new() }
    }
    $root = Switch ($Provider) {
        'GCP' { '/workspace/index.js' }
        'AWS' { '/var/task/index.mjs' }
        'Azure' { '/home/site/wwwroot/v1/index.js' }
        Default { Throw [System.NotImplementedException]::new() }
    }
    $fullCommand = `
"const require = await ((async function () {
  const { createRequire } = await import('node:module')
  return createRequire($(ConvertTo-Json $root))
})())
$Command"
    $key = Get-Content -LiteralPath "$PSScriptRoot/$($Provider.ToLowerInvariant())/.key" -Encoding utf8
    $time = [long](([datetime]::UtcNow.Ticks - 621355968000000000) / 10000)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($key))
    $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("<$time|$fullCommand>")).ForEach({$_.ToString('x2')}) -join ''
    $body = ConvertTo-Json -Compress @{
        time=$time
        command=$fullCommand
        hash=$hash
    }
    $reponse = Invoke-WebRequest `
        -Uri $url `
        -Method Post `
        -Body $body `
        -ContentType 'application/json'
    If ($Raw) {
        $reponse.Content
    }
    Else {
        ConvertFrom-Json -InputObject $reponse.Content
    }
}


Filter Initialize-CloudFiles {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    )

    Invoke-CloudFunction -Provider $Provider -Region $Region -Command `
"const { randomBytes } = await import('node:crypto')
const { Buffer } = await import('node:buffer')
const crcTable = []
for (let n = 0; n < 256; n++) {
  let c = n
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1)
  }
  crcTable.push(c)
}
const crc = (buffer) => {
  let c = 0xffffffff
  for (let i = 0; i < buffer.length; i++) {
    c = crcTable[(c ^ buffer[i]) & 0xff] ^ (c >>> 8)
  }
  c = c ^ 0xffffffff
  const result = Buffer.alloc(4)
  result.writeInt32BE(c, 0)
  return result
}
const chunk = (type, data) => {
  const typeBuffer = Buffer.from(type)
  const lengthBuffer = Buffer.alloc(4)
  lengthBuffer.writeUInt32BE(data.length, 0)
  return Buffer.concat([lengthBuffer, typeBuffer, data, crc(Buffer.concat([typeBuffer, data]))])
}
const pngHeader = (() => {
  const data = Buffer.alloc(13)
  data.writeUInt32BE(1000, 0) //width
  data.writeUInt32BE(1000, 4) //height
  data.writeUInt8(8, 8) //bitDepth
  data.writeUInt8(2, 9) //colorType (RGB)
  data.writeUInt8(0, 10) //compressionMethod
  data.writeUInt8(0, 11) //filterMethod
  data.writeUInt8(0, 12) //interlaceMethod
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', data)])
})()
const pngTrailer = Buffer.concat([chunk('IEND', Buffer.alloc(0))]) //missing IDAT on purpose
const png = (chunkData, count) => {
  const chunks = [pngHeader]
  while (count-- > 0) {
    chunks.push(chunk('fiLl', chunkData()))
  }
  chunks.push(pngTrailer)
  return Buffer.concat(chunks)
}
const sizes = [512, 10*1024, 1024*1024, 10*1024*1024]
const files = [
  ['zero.bin', () => Buffer.alloc(0)],
  ['image_ping.png', () => png(() => null, 0)],
  ['image_full.png', () => png(() => randomBytes(10*1024), 408)],
  ...sizes.map(size => [``zero_`${size}.bin``, () => Buffer.alloc(size)]),
  ...sizes.map(size => [``random_`${size}.bin``, () => randomBytes(size)])
]
$(Switch ($Provider) {
'AWS' {
"
const s3 = $AWS_S3
const errors = []
for (const [file, content] of files) {
  try {
    await s3.putObject({
      ...$AWS_Bucket,
      Body: content(),
      Key: file,
    }).promise()
  } catch (err) {
    errors.push({
      Provider: 'AWS',
      Region: process.env.REGION,
      File: file,
      Reason: String(err)
    })
  }
}
return errors
"
} 'GCP' {
"
const bucket = $GCP_StorageBucket
const errors = []
for (const [file, content] of files) {
  try {
    await bucket.file(file).save(content())
  } catch (err) {
    errors.push({
      Provider: 'GCP',
      Region: process.env.REGION,
      File: file,
      Reason: String(err)
    })
  }
}
return errors
"
} 'Azure' {
"
const containerClient = $Azure_ContainerClient
const errors = []
for (const [file, content] of files) {
  const blockBlockClient = containerClient.getBlockBlobClient(file)
  try {
    await blockBlockClient.uploadData(content())
  } catch (err) {
    errors.push({
      Provider: 'Azure',
      Region: process.env.REGION,
      File: file,
      Reason: String(err)
    })
  }
}
return errors
"
} Default { Throw [System.NotImplementedException]::new() }
})"
}


Filter Copy-CloudFile {
    Param (
        [Parameter(Mandatory=$true, ParameterSetName='uri')]
        [uri] $SourceUri
    ,
        [Parameter(Mandatory=$true, ParameterSetName='bytes')]
        [byte[]] $SourceBytes
    ,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    ,
        [Parameter(Mandatory=$true)]
        [string] $DestinationName
    )

    Invoke-CloudFunction -Provider $Provider -Region $Region -Command `
"const { Buffer } = await import('node:buffer')
const name = $(ConvertTo-Json $DestinationName)
const data = $(Switch ($PSCmdlet.ParameterSetName) {
    'uri' { "Buffer.from(await (await fetch($(ConvertTo-Json $SourceUri))).arrayBuffer())" }
    'bytes' { "Buffer.from($(ConvertTo-Json ([System.Convert]::ToBase64String($SourceBytes))), 'base64')" }
    Default { Throw [System.NotImplementedException]::new() }
})
$(Switch ($Provider) {
    'AWS' { "await $AWS_S3.putObject({ Body: data, Bucket: process.env.BUCKET, Key: name }).promise()" }
    'GCP' { "await $GCP_StorageBucket.file(name).save(data)" }
    'Azure' { "await $Azure_ContainerClient.getBlockBlobClient(name).uploadData(data)" }
    Default { Throw [System.NotImplementedException]::new() }
})"
}


Filter Test-CloudFile {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    ,
        [Parameter(Mandatory=$true)]
        [string] $Name
    )

    Invoke-CloudFunction -Provider $Provider -Region $Region -Command `
"const name = $(ConvertTo-Json $Name)
$(Switch ($Provider) {
    'AWS' {
"try {
  await $AWS_S3.headObject({ ...$AWS_Bucket, Key: name }).promise()
  return true
} catch (err) {
  if (err.code !== 'NotFound') {
    throw err
  }
  return false
}"
    }
    'GCP' { "return await $GCP_StorageBucket.file(name).exists()" }
    'Azure' { "return (await $Azure_ContainerClient.getBlockBlobClient(name).exists()).toString()" }
    Default { Throw [System.NotImplementedException]::new() }
})"
}


Filter Clear-CloudFiles {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    )

    Invoke-CloudFunction -Provider $Provider -Region $Region -Command `
"$(Switch ($Provider) {
'AWS' {
"
const s3 = $AWS_S3
const errors = []
let marker = ''
while (true) {
  const listObjects = await s3.listObjects({ ...$AWS_Bucket, Marker: marker }).promise()
  if (listObjects.Contents.length === 0) {
    break
  }
  const deleteObjects = await s3.deleteObjects({
    ...$AWS_Bucket,
    Delete: {
      Objects: listObjects.Contents.map(e => ({ Key: e.Key })),
      Quiet: true
    }
  }).promise()
  errors.push(...deleteObjects.Errors.map(e => ({
    Provider: 'AWS',
    Region: process.env.REGION,
    File: e.Key,
    Reason: e.Code
  })))
  if (!listObjects.IsTruncated) {
    break
  }
  marker = listObjects.Marker
}
return errors
"
} 'GCP' {
"
const bucket = $GCP_StorageBucket
const [files] = await bucket.getFiles()
const errors = []
for (const file of files) {
  try {
    await bucket.file(file.name).delete()
  } catch (err) {
    errors.push({
      Provider: 'GCP',
      Region: process.env.REGION,
      File: file.name,
      Reason: String(err)
    })
  }
}
return errors
"
} 'Azure' {
"
const containerClient = $Azure_ContainerClient
const errors = []
for await (const blob of containerClient.listBlobsFlat()) {
  try {
    await containerClient.deleteBlob(blob.name)
  } catch (err) {
    errors.push({
      Provider: 'Azure',
      Region: process.env.REGION,
      File: blob.name,
      Reason: String(err)
    })
  }
}
return errors
"
} Default { Throw [System.NotImplementedException]::new() }
})"
}


Filter Get-CloudFileRoot {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    )

    If ($Region -notin $Regions[$Provider]) { Throw "Unknown region '$Region', supported are $($Regions[$Provider] -join ', ')." }
    $location = $Region.ToLowerInvariant()
    Switch ($Provider) {
        'GCP'   { "https://storage.googleapis.com/$GCP_Project-$location/" }
        'AWS'   { "https://$AWS_Prefix-$location.s3.$location.amazonaws.com/" }
        'Azure' { "https://$Azure_Group$location.blob.core.windows.net/$Azure_Container/" }
        Default { Throw [System.NotImplementedException]::new() }
    }
}


Filter Test-CloudFileTransfer {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $FromProvider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FromRegion
    ,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('GCP','AWS','Azure')]
        [string] $ToProvider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $ToRegion
    )

    Invoke-CloudFunction -Provider $ToProvider -Region $ToRegion -Command `
"const https = await import('node:https')
const root = $(Get-CloudFileRoot -Provider $FromProvider -Region $FromRegion | ConvertTo-Json)
const sizes = [512, 10*1024, 1024*1024, 10*1024*1024]
const files = [
  ['zero.bin', 0],
  ...sizes.map(size => [``zero_`${size}.bin``, size]),
  ...sizes.map(size => [``random_`${size}.bin``, size])
]
const results = []
for (const [file, expectedSize] of files) {
  try {
    const hrt = process.hrtime()
    const downloadedSize = await new Promise((resolve, reject) => https.get(root + file, (res) => {
      if (res.statusCode !== 200) {
        res.destroy(``Status code `${res.statusCode} received.``)
      } else {
        let total = 0
        res.on('data', (chunk) => { total += chunk.length })
        res.on('end', () => { resolve(total) })
      }
    }).on('error', reject))
    const time = process.hrtime(hrt)
    if (downloadedSize !== expectedSize) {
      throw Error(``Received `${downloadedSize}, expected `${expectedSize}.``)
    }
    results.push({ file, time })
  } catch (err) {
    results.push({ file, error: String(err) })
  }
}
return results"
}


Filter Test-CloudOcrTransfer {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    )

    $fetchTesk = `
"const hrt = process.hrtime()
const response = await fetch(task.uri, task.options)
const time = process.hrtime(hrt)"
    If ($Region -notin $OcrRegions[$Provider]) { Throw "Unknown OCR region '$Region', supported are $($OcrRegions[$Provider] -join ', ')." }
    Invoke-CloudFunction -Provider $Provider -Region $Region -Command `
"const files = [
  ['image_ping.png', 45],
  ['image_full.png', 4182861]
]
const results = []
for (const [file, expectedSize] of files) {
  for (let batch = 1; batch <= 5; batch++) {
    try {
$(Switch ($Provider) {
'AWS' {
"
      const task = await $AWS_Ocr(file)
      $fetchTesk
      if (response.status !== 400) {
        throw ``DetectText finished with `${response.status} `${response.statusText}.``
      }
      const failure = await response.json()
      if (failure.__type !== 'InvalidImageFormatException') {
        throw ``DetectText failed with `${failure.__type}.``
      }
"
} 'GCP' {
"
      const task = await $GCP_Ocr(file)
      $fetchTesk
      const error = (await response.json()).responses[0].error
      if (!error) {
        throw 'Annotate did not return an error.'
      }
      if (error.message !== 'Bad image data.') {
        throw ``Annotate failed with `${error.message}.``
        // very likely 'Annotate failed with We can not access the URL currently. Please download the content and pass it in.'
      }
"
} 'Azure' {
"
      const task = await $Azure_Ocr(file, $(ConvertTo-Json $Azure_CognitiveKeys[$Region]))
      $fetchTesk
      if (response.status !== 400) {
        throw ``OCR finished with `${response.status} `${response.statusText}.``
      }
      const failure = await response.json()
      if (failure.error.innererror.code !== 'InvalidImageFormat') {
        throw ``OCR failed with `${failure.error.innererror.code}.``
      }
"
} Default { Throw [System.NotImplementedException]::new() }
})
      results.push({ batch, file, ocr: true, time })
    }
    catch (err) {
      results.push({ batch, file, ocr: true, error: String(err) })
    }
    try {
      const hrt = process.hrtime()
      response = await fetch(url, { cache: 'no-cache' })
      if (!response.ok) {
        throw ``Failed download with `${response.status} `${response.statusText}.``
      }
      const downloadedSize = (await response.blob()).size
      const time = process.hrtime(hrt)
      if (downloadedSize !== expectedSize) {
        throw Error(``Received `${downloadedSize}, expected `${expectedSize}.``)
      }
      results.push({ batch, file, ocr: false, time })
    }
    catch (err) {
      results.push({ batch, file, ocr: false, error: String(err) })
    }
  }
}
return results"
}


Filter Invoke-CloudOcr {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('AWS','Azure','GCP')]
        [string] $Provider
    ,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $Region
    ,
        [Parameter(Mandatory=$true)]
        [string] $FileName
    )

    If ($Region -notin $OcrRegions[$Provider]) { Throw "Unknown OCR region '$Region', supported are $($OcrRegions[$Provider] -join ', ')." }
    Invoke-CloudFunction -Provider $Provider -Region $Region -Command `
"const fileName = $(ConvertTo-Json $FileName)
const task = await $(Switch ($Provider) {
    'AWS' { "$AWS_Ocr(fileName)" }
    'GCP' { "$GCP_Ocr(fileName)" }
    'Azure' { "$Azure_Ocr(fileName, $(ConvertTo-Json $Azure_CognitiveKeys[$Region]))" }
    Default { Throw [System.NotImplementedException]::new() }
})
const hrt = process.hrtime()
const response = await fetch(task.uri, task.options)
const time = process.hrtime(hrt)
const result = await response.json()
return {
  ...result,
  Status: response.status,
  Time: time[0] + time[1] / 1000000000
}"
}


# Prepare:
# $All | ForEach-Object -ThrottleLimit 20 -Parallel { . .\invoke.ps1; $current = $_.Provider + '-' + $_.Region; Write-Host "Prepare $current..."; Try { $_ | Initialize-CloudFiles } Catch { Write-Warning "$current failed: $_" } }

# File Transfer Test:
# $transfers = $All.foreach({ $from=$_; $All.foreach({New-Object -TypeName PSObject -Property @{ FromProvider=$from.Provider; FromRegion=$from.Region; ToProvider=$_.Provider; ToRegion=$_.Region }})})
# $transfers | Sort-Object { Get-Random } | ForEach-Object -ThrottleLimit 20 -Parallel { $name = $_.FromProvider + '-' + $_.FromRegion + '_' + $_.ToProvider + '-' + $_.ToRegion + '.json'; $path = Join-Path -Path 'results' -ChildPath $name; If (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Write-Host "Collect $name..."; Try { . .\invoke.ps1; $_ | Test-CloudFileTransfer | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $path -Encoding UTF8 } Catch { Write-Warning "$name failed: $_" } } }
# $transfers | ForEach-Object -ThrottleLimit 20 -Parallel {
#     $transfer = $_
#     $name = $_.FromProvider + '-' + $_.FromRegion + '_' + $_.ToProvider + '-' + $_.ToRegion + '.json'
#     $path = Join-Path -Path 'results' -ChildPath $name
#     Get-Content -LiteralPath $path -Encoding UTF8 | ConvertFrom-Json | ForEach-Object {
#         If (-not ($_ | Get-Member -Name 'error')) {
#             New-Object -TypeName 'PSObject' -Property @{
#                FromProvider = $transfer.FromProvider
#                FromRegion = $transfer.FromRegion
#                ToProvider = $transfer.ToProvider
#                ToRegion = $transfer.ToRegion
#                File = $_.file
#                Time = $_.time[0] + ($_.time[1] / 1000000000)
#             }
#         }
#         Else {
#             Write-Warning "$($_.file) in $name failed: $($_.error)"
#         }
#     }
# } | Export-Csv -LiteralPath 'results.csv' -NoClobber -NoTypeInformation -Encoding UTF8

# OCR Transfer Test
# $OcrAll | ForEach-Object -ThrottleLimit 20 -Parallel { $name = $_.Provider + '-' + $_.Region + '.json'; $path = Join-Path -Path 'results' -ChildPath $name; If (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Write-Host "Collect $name..."; Try { . .\invoke.ps1; $_ | Test-CloudOcrTransfer | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $path -Encoding UTF8 } Catch { Write-Warning "$name failed: $_" } } }
# $OcrAll | ForEach-Object -ThrottleLimit 20 -Parallel {
#     $ocr = $_
#     $name = $_.Provider + '-' + $_.Region + '.json'
#     $path = Join-Path -Path 'results' -ChildPath $name
#     Get-Content -LiteralPath $path -Encoding UTF8 | ConvertFrom-Json | ForEach-Object {
#         If (-not ($_ | Get-Member -Name 'error')) {
#             New-Object -TypeName 'PSObject' -Property @{
#                Provider = $ocr.Provider
#                Region = $ocr.Region
#                Batch = $_.Batch
#                OCR = $_.OCR
#                File = $_.file
#                Time = $_.time[0] + ($_.time[1] / 1000000000)
#             }
#         }
#         Else {
#             Write-Warning "$($_.file) batch #$($_.batch) in $name failed: $($_.error)"
#         }
#     }
# } | Export-Csv -LiteralPath 'results.csv' -NoClobber -NoTypeInformation -Encoding UTF8

# Cleanup:
# $All | ForEach-Object -ThrottleLimit 20 -Parallel { . .\invoke.ps1; $current = $_.Provider + '-' + $_.Region; Write-Host "Cleanup $current..."; Try { $_ | Clear-CloudFiles } Catch { Write-Warning "$current failed: $_" } }
