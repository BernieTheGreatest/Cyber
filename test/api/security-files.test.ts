/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { register, login } from './helpers/auth'

let app: Express
let token: string
before(async () => {
  app = (await createTestApp()).app
  await register(app, { email: 'file-owner@example.org', password: 'password' })
  token = (await login(app, { email: 'file-owner@example.org', password: 'password' })).token
}, { timeout: 60000 })

void describe('production profile boundaries', () => {
  void it('renders an ordinary profile and never evaluates a stored username', async () => {
    const payload = "#{process.env.SECURITY_PROFILE_TEST='executed'}"
    await request(app).post('/profile').set('Cookie', `token=${token}`).type('form').send({ username: payload }).expect(302)
    const response = await request(app).get('/profile').set('Cookie', `token=${token}`).expect(200)
    assert.notEqual(process.env.SECURITY_PROFILE_TEST, 'executed')
    assert.ok(response.text.includes('SECURITY_PROFILE_TEST'))
    await request(app).post('/profile').set('Cookie', `token=${token}`).type('form').send({ username: 'Ordinary User' }).expect(302)
    const normal = await request(app).get('/profile').set('Cookie', `token=${token}`).expect(200)
    assert.ok(normal.text.includes('Ordinary User'))
  })
  void it('rejects remote image requests across internal addresses and redirect sources', async () => {
    for (const imageUrl of ['http://127.0.0.1/private', 'http://[::1]/private', 'http://169.254.169.254/', 'https://example.org/redirect']) {
      await request(app).post('/profile/image/url').set('Cookie', `token=${token}`).type('form').send({ imageUrl }).expect(410)
    }
  })
})
