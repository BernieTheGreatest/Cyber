/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

export function profileImageUrlUpload () {
  return async (_req: Request, res: Response) => {
    res.status(410).json({ error: 'Remote image imports are disabled; upload an image file instead.' })
  }
}
