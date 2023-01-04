export const handler = async (event) => {
  const AsyncFunction = (async function () { }).constructor
  const badRequest = (body) => ({ statusCode: 400, body })
  const forbidden = (body) => ({ statusCode: 403, body })
  const internalServerError = (body) => ({ statusCode: 500, body })
  const success = (body) => ({ statusCode: 200, body })
  const key = process.env.HMAC_KEY
  const request = JSON.parse(event.body)

  try {
    if (typeof request !== 'object') { return badRequest('Body must be a JSON object.') }
    if (typeof request.time !== 'number') { return badRequest('Time must be a number.') }
    if (Math.abs(Date.now() - request.time) > 60000) { return badRequest('Time difference is too big.') }
    if (typeof request.command !== 'string') { return badRequest('Command must be a string.') }
    if (typeof request.hash !== 'string') { return badRequest('Hash must be a string.') }
    if (typeof key !== 'string' || key.length < 16) { return internalServerError('Invalid key.') }
    const { createHmac } = await import('node:crypto')
    const hmac = createHmac('sha256', key)
    hmac.update(`<${request.time}|${request.command}>`)
    if (hmac.digest('hex') !== request.hash) { return forbidden('Hash mismatch.') }
    return success(await AsyncFunction(request.command).call(null))
  } catch (e) {
    return internalServerError(String(e))
  }
}
