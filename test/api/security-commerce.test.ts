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
import * as security from '../../lib/insecurity'
import { WalletModel } from '../../models/wallet'
import { BasketItemModel } from '../../models/basketitem'
import { ordersCollection } from '../../data/mongodb'

let app: Express
let customer: any
let userId: number
before(async () => {
  app = (await createTestApp()).app
  await register(app, { email: 'commerce-owner@example.org', password: 'password' })
  customer = await login(app, { email: 'commerce-owner@example.org', password: 'password' })
  userId = security.decode(customer.token).data.id
}, { timeout: 60000 })
const auth = () => ({ Authorization: `Bearer ${customer.token}` })

void describe('production commerce boundaries', () => {
  void it('rejects negative, zero, fractional, string and nonnumeric quantities', async () => {
    for (const quantity of [-1, 0, 1.5, '1', 'invalid']) {
      await request(app).post('/api/BasketItems').set(auth()).send({ ProductId: 1, BasketId: customer.bid, quantity }).expect(400)
    }
    assert.equal(await BasketItemModel.count({ where: { BasketId: customer.bid } }), 0)
    await request(app).post('/api/BasketItems').set(auth()).send({ ProductId: 1, BasketId: customer.bid, quantity: 1 }).expect(200)
    const item = await BasketItemModel.findOne({ where: { BasketId: customer.bid } })
    await request(app).put(`/api/BasketItems/${item?.id}`).set(auth()).send({ quantity: 0 }).expect(400)
    assert.equal((await item?.reload())?.quantity, 1)
  })
  void it('rejects client-selected wallet credits without changing balances', async () => {
    const before = await WalletModel.findOne({ where: { UserId: userId } })
    const originalBalance = before?.balance
    for (const balance of [100, -100, 1e20]) await request(app).put('/rest/wallet/balance').set(auth()).send({ balance, paymentId: 1 }).expect(503)
    assert.equal((await before?.reload())?.balance, originalBalance)
    await request(app).get('/rest/wallet/balance').set(auth()).expect(200)
  })
  void it('accepts issued coupons but rejects tampering, forged encodings and invalid discounts', async () => {
    const coupon = security.generateCoupon(10)
    assert.equal(security.discountFromCoupon(coupon), 10)
    assert.equal(security.discountFromCoupon(coupon.slice(0, -6) + 'abcdef'), undefined)
    assert.equal(security.discountFromCoupon('n<MiifFb4l'), undefined)
    assert.equal(security.discountFromCoupon(security.generateCoupon(10, new Date(2000, 0, 1))), undefined)
    for (const discount of [0, -1, 101, 1.5, NaN]) assert.throws(() => security.generateCoupon(discount))
    await request(app).put(`/rest/basket/${customer.bid}/coupon/${encodeURIComponent(coupon)}`).set(auth()).expect(200)
    await request(app).get('/api/Feedbacks/1').set('Authorization', `Bearer ${coupon}`).expect(401)
    await request(app).get('/api/Feedbacks/1').set('Authorization', `Bearer ${security.authorize({ userId, type: 'password_valid_needs_second_factor_token' })}`).expect(401)
  })
  void it('preserves ordinary checkout and binds resulting orders to an immutable customer id', async () => {
    const balance = (await WalletModel.findOne({ where: { UserId: userId } }))?.balance
    for (const orderDetails of [{}, { paymentId: 123 }]) await request(app).post(`/rest/basket/${customer.bid}/checkout`).set(auth()).send({ orderDetails }).expect(402)
    assert.equal((await WalletModel.findOne({ where: { UserId: userId } }))?.balance, balance)
    await WalletModel.update({ balance: 100 }, { where: { UserId: userId } })
    const order = await request(app).post(`/rest/basket/${customer.bid}/checkout`).set(auth()).send({ orderDetails: { paymentId: 'wallet' } }).expect(200)
    const saved = await ordersCollection.findOne({ orderId: order.body.orderConfirmation })
    assert.equal(saved.UserId, userId)
    assert.ok(saved.totalPrice >= 0)
  })
  void it('rejects forged and missing chat identity before provider access', async () => {
    await request(app).post('/rest/chat').send({ messages: [] }).expect(401)
    await request(app).post('/rest/chat').set('Authorization', 'Bearer eyJhbGciOiJub25lIn0.eyJkYXRhIjp7ImlkIjoxfX0.').send({ messages: [] }).expect(401)
  })
})
