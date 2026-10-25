/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import crypto from 'node:crypto'
import fs from 'node:fs'
import jwt from 'jsonwebtoken'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
before(async () => { app = (await createTestApp()).app }, { timeout: 60000 })

void describe('production identity boundaries', () => {
  void it('preserves registration and ordinary password login', async () => {
    await request(app).post('/api/Users').send({ email: 'security-login@example.org', password: 'test-password' }).expect(201)
    const res = await request(app).post('/rest/user/login').send({ email: 'security-login@example.org', password: 'test-password' }).expect(200)
    assert.equal(security.decode(res.body.authentication.token).data.email, 'security-login@example.org')
  })

  void it('rejects SQL authentication injection and structured credentials', async () => {
    for (const email of ["' OR 1=1--", "admin@juice-sh.op'--", { $ne: null }]) {
      await request(app).post('/rest/user/login').send({ email, password: 'wrong-password' }).expect(401)
    }
  })

  void it('treats search SQL as data and preserves ordinary search', async () => {
    const normal = await request(app).get('/rest/products/search').query({ q: 'Apple' }).expect(200)
    assert.ok(normal.body.data.length > 0)
    const injected = await request(app).get('/rest/products/search').query({ q: "')) UNION SELECT * FROM Users--" }).expect(200)
    assert.deepEqual(injected.body.data, [])
    await request(app).get('/rest/products/search?q[a]=x').expect(400)
  })

  void it('uses a new signing authority and rejects invalid signatures, algorithms and expiration', () => {
    const bundled = crypto.createPublicKey(fs.readFileSync('encryptionkeys/jwt.pub')).export({ type: 'spki', format: 'pem' }).toString()
    assert.notEqual(security.publicKey, bundled)
    assert.equal(security.verify(security.authorize({ data: { id: 1 } })), true)
    assert.equal(security.verify(jwt.sign({ data: { id: 1 } }, security.publicKey, { algorithm: 'HS256' })), false)
    const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    assert.equal(security.verify(jwt.sign({ data: { id: 1 } }, other, { algorithm: 'RS256' })), false)
    assert.equal(security.verify(jwt.sign({ data: { id: 1 } }, other, { algorithm: 'RS256', expiresIn: -1 })), false)
    assert.equal(security.decode('malformed'), undefined)
  })
})
