/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { BasketModel } from '../models/basket'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const basketId = req.body.BasketId
    const basket = user && await BasketModel.findOne({ where: { id: basketId, UserId: user.data.id } })
    if (!basket) {
      res.status(403).json({ error: 'Forbidden' })
    } else {
      const basketItem = {
        ProductId: req.body.ProductId,
        BasketId: basket.id,
        quantity: req.body.quantity
      }

      const basketItemInstance = BasketItemModel.build(basketItem)
      try {
        const addedBasketItem = await basketItemInstance.save()
        res.json({ status: 'success', data: addedBasketItem })
      } catch (error) {
        next(error)
      }
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (req.body.quantity) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity).catch((error: Error) => {
          next(error)
        })
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}

export function listBasketItems () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) return res.status(401).json({ error: 'Unauthorized' })
    const basket = await BasketModel.findOne({ where: { UserId: user.data.id } })
    const items = basket ? await BasketItemModel.findAll({ where: { BasketId: basket.id } }) : []
    res.json({ status: 'success', data: items })
  }
}

export function authorizeBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const item = await BasketItemModel.findByPk(req.params.id)
    const basket = user && item && await BasketModel.findOne({ where: { id: item.BasketId, UserId: user.data.id } })
    if (!basket) return res.status(403).json({ error: 'Forbidden' })
    if ((req.body.BasketId !== undefined && Number(req.body.BasketId) !== basket.id) || (req.body.ProductId !== undefined && Number(req.body.ProductId) !== item.ProductId)) return res.status(403).json({ error: 'Forbidden' })
    next()
  }
}
