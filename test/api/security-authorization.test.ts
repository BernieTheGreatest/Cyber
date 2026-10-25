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
import { BasketItemModel } from '../../models/basketitem'
import { AddressModel } from '../../models/address'
import * as security from '../../lib/insecurity'
import { reviewsCollection } from '../../data/mongodb'

let app: Express
let first: any, second: any
before(async () => {
  app = (await createTestApp()).app
  for (const email of ['owner-a@example.org', 'owner-b@example.org']) await register(app, { email, password: 'test-password' })
  first = await login(app, { email: 'owner-a@example.org', password: 'test-password' })
  second = await login(app, { email: 'owner-b@example.org', password: 'test-password' })
}, { timeout: 60000 })
const auth = () => ({ Authorization: `Bearer ${first.token}` })

void describe('production authorization boundaries', () => {
  void it('rejects privileged registration fields', async () => {
    for (const fields of [{ role: 'admin' }, { role: 'accounting' }, { id: 1 }, { deluxeToken: 'x' }, { totpSecret: 'x' }]) {
      await request(app).post('/api/Users').send({ email: 'privileged@example.org', password: 'password', ...fields }).expect(400)
    }
  })
  void it('rejects customer enumeration and anonymous/customer catalog writes', async () => {
    await request(app).get('/api/Users').set(auth()).expect(403)
    await request(app).put('/api/Products/1').send({ price: 0 }).expect(401)
    await request(app).put('/api/Products/1').set(auth()).send({ price: 0 }).expect(403)
    await request(app).post('/api/Products').set(auth()).send({ name: 'forged' }).expect(403)
    await request(app).get('/api/Products/1').expect(200)
  })
  void it('preserves own basket access and rejects foreign reads, coupons and checkout', async () => {
    await request(app).get(`/rest/basket/${first.bid}`).set(auth()).expect(200)
    await request(app).get(`/rest/basket/${second.bid}`).set(auth()).expect(403)
    await request(app).post(`/rest/basket/${second.bid}/checkout`).set(auth()).send({}).expect(403)
    await request(app).put(`/rest/basket/${second.bid}/coupon/x`).set(auth()).expect(403)
  })
  void it('scopes item reads, edits, deletes and duplicate-key creation', async () => {
    const item = await BasketItemModel.create({ BasketId: second.bid, ProductId: 1, quantity: 1 })
    for (const method of ['get', 'put', 'delete'] as const) await request(app)[method](`/api/BasketItems/${item.id}`).set(auth()).send({ quantity: 2 }).expect(403)
    const list = await request(app).get('/api/BasketItems').set(auth()).expect(200)
    assert.ok(list.body.data.every((entry: any) => entry.BasketId === first.bid))
    await request(app).post('/api/BasketItems').set(auth()).set('Content-Type', 'application/json').send(`{"ProductId":1,"BasketId":${first.bid},"quantity":1,"BasketId":${second.bid}}`).expect(403)
    assert.equal((await item.reload()).quantity, 1)
    const own = await BasketItemModel.create({ BasketId: first.bid, ProductId: 1, quantity: 1 })
    await request(app).put(`/api/BasketItems/${own.id}`).set(auth()).send({ ProductId: 2 }).expect(403)
    assert.equal((await own.reload()).ProductId, 1)
  })
  void it('does not transfer a foreign address on update', async () => {
    const victimId = security.decode(second.token).data.id
    const address = await AddressModel.create({ UserId: victimId, fullName: 'Victim', mobileNum: 1234567, zipCode: '12345', streetAddress: 'Test street', city: 'Test', country: 'Test' })
    await request(app).put(`/api/Addresss/${address.id}`).set(auth()).send({ fullName: 'Attacker' }).expect(403)
    assert.equal((await address.reload()).fullName, 'Victim')
  })
  void it('keeps complaint lists owner-scoped', async () => {
    await request(app).post('/api/Complaints').set({ Authorization: `Bearer ${second.token}` }).send({ message: 'private complaint' }).expect(201)
    const res = await request(app).get('/api/Complaints').set(auth()).expect(200)
    assert.ok(res.body.data.every((entry: any) => entry.message !== 'private complaint'))
  })
  void it('rejects operator selectors and preserves foreign reviews', async () => {
    await reviewsCollection.insert({ product: '1', author: 'owner-b@example.org', message: 'original', likesCount: 0, likedBy: [] })
    const inserted = await reviewsCollection.findOne({ author: 'owner-b@example.org', message: 'original' })
    await request(app).patch('/rest/products/reviews').set(auth()).send({ id: { $ne: null }, message: 'forged' }).expect(400)
    await request(app).patch('/rest/products/reviews').set(auth()).send({ id: inserted._id, message: 'forged' }).expect(200)
    assert.equal((await reviewsCollection.findOne({ _id: inserted._id })).message, 'original')
    await request(app).put('/rest/products/1/reviews').send({ message: 'anonymous', author: 'owner-b@example.org' }).expect(401)
    await request(app).put('/rest/products/1/reviews').set(auth()).send({ message: 'legitimate', author: 'owner-b@example.org' }).expect(201)
    assert.equal((await reviewsCollection.findOne({ message: 'legitimate' })).author, 'owner-a@example.org')
  })
})
