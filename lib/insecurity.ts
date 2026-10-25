/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from '@juice-shop/models/user'
import jwt from 'jsonwebtoken'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

const signingKey = process.env.JWT_PRIVATE_KEY
  ? crypto.createPrivateKey(process.env.JWT_PRIVATE_KEY)
  : crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
const privateKey = signingKey.export({ type: 'pkcs8', format: 'pem' }).toString()
export const publicKey = crypto.createPublicKey(signingKey).export({ type: 'spki', format: 'pem' }).toString()
const bundledPublicKey = crypto.createPublicKey(fs.readFileSync('encryptionkeys/jwt.pub')).export({ type: 'spki', format: 'pem' }).toString()
if (publicKey === bundledPublicKey) throw new Error('The bundled JWT signing key must be rotated')

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (str.includes(nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => (req: Request, res: Response, next: NextFunction) => {
  const payload = decode(utils.jwtFrom(req))
  if (Number.isSafeInteger(payload?.data?.id) && payload.data.id > 0) next()
  else res.status(401).json({ error: 'Authentication required' })
}
export const isAdmin = () => (req: Request, res: Response, next: NextFunction) => {
  if (decode(utils.jwtFrom(req))?.data?.role === roles.admin) next()
  else res.status(403).json({ error: 'Forbidden' })
}
export const denyAll = () => (_req: Request, res: Response, _next: NextFunction) => {
  res.status(403).json({ error: 'Forbidden' })
}
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const decode = (token?: string): any => {
  try {
    if (!token) return undefined
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] })
  } catch {
    return undefined
  }
}
export const verify = (token?: string) => decode(token) !== undefined

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token && verify(utils.unquote(token)) ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  if (!Number.isInteger(discount) || discount < 1 || discount > 100 || !Number.isFinite(date.getTime())) throw new Error('Invalid coupon')
  return jwt.sign({ type: 'discount_coupon', month: utils.toMMMYY(date), discount }, privateKey, { algorithm: 'RS256', expiresIn: '31d' })
}

export const discountFromCoupon = (coupon?: string) => {
  const payload = decode(coupon)
  if (payload?.type === 'discount_coupon' && payload.month === utils.toMMMYY(new Date()) && Number.isInteger(payload.discount) && payload.discount >= 1 && payload.discount <= 100) return payload.discount as number
  return undefined
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = authenticatedUsers.from(req)
      if (!user?.data?.id) throw new Error('Authentication required')
      req.body.UserId = user.data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && authenticatedUsers.get(token) === undefined) {
    const decoded = decode(token)
    if (decoded?.data !== undefined) {
      authenticatedUsers.put(token, decoded)
      res.cookie('token', token)
    }
  }
  next()
}
