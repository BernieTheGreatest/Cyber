/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import yaml from 'js-yaml'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import { parseXmlString } from '../lib/xml'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

export async function extractZipBuffer (buffer: Buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  if (directory.files.length > 100) throw new Error('Too many archive entries')
  const root = path.resolve('uploads/complaints')
  await fs.promises.mkdir(root, { recursive: true })
  const realRoot = await fs.promises.realpath(root)
  const entries = directory.files.map(entry => {
    const name = entry.path
    const destination = path.resolve(root, name)
    const relative = path.relative(root, destination)
    const mode = entry.externalFileAttributes >>> 16
    if (!name || path.isAbsolute(name) || path.win32.isAbsolute(name) || name.includes('\\') || name.split('/').includes('..') || relative.startsWith('..') || path.isAbsolute(relative) || (mode & 0o170000) === 0o120000) {
      throw new Error('Invalid archive path')
    }
    if (entry.uncompressedSize > 5 * 1024 * 1024) throw new Error('Archive is too large')
    return { entry, destination }
  })
  let total = 0
  for (const { entry, destination } of entries) {
    const parent = entry.type === 'Directory' ? destination : path.dirname(destination)
    await fs.promises.mkdir(parent, { recursive: true })
    const realParent = await fs.promises.realpath(parent)
    const relativeParent = path.relative(realRoot, realParent)
    if (relativeParent.startsWith('..') || path.isAbsolute(relativeParent)) throw new Error('Invalid archive path')
    if (entry.type === 'Directory') continue
    const limit = new Transform({
      transform (chunk, _encoding, callback) {
        total += chunk.length
        callback(total > 5 * 1024 * 1024 ? new Error('Archive is too large') : null, chunk)
      }
    })
    try {
      await pipeline(entry.stream(), limit, fs.createWriteStream(destination, { flags: 'wx' }))
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') await fs.promises.unlink(destination).catch(() => {})
      throw error
    }
  }
}

async function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!(file?.originalname?.toLowerCase().endsWith('.zip') ?? false)) {
    next()
    return
  }
  if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
    try {
      await extractZipBuffer(file.buffer)
    } catch (err) {
      next(err)
      return
    }
  }
  res.status(204).end()
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  const allowedFileTypes = ['pdf', 'xml', 'zip', 'yml', 'yaml']
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !fileType || !allowedFileTypes.includes(fileType)
  })
  next()
}

async function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!(file?.originalname?.toLowerCase().endsWith('.xml') ?? false)) {
    next()
    return
  }
  challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
  if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
    const data = file.buffer.toString()
    try {
      const xmlString = await parseXmlString(data)
      challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) })
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      if (errorMessage.includes('Script execution timed out')) {
        if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
          challengeUtils.solve(challenges.xxeDosChallenge)
        }
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
      } else {
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
      }
    }
  } else {
    res.status(410)
    next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
  }
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!((file?.originalname?.toLowerCase().endsWith('.yml') ?? false) || (file?.originalname?.toLowerCase().endsWith('.yaml') ?? false))) {
    res.status(204).end()
    return
  }
  challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
  if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
    const data = file.buffer.toString()
    try {
      const sandbox = { yaml, data }
      vm.createContext(sandbox)
      const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      if (errorMessage.includes('Invalid string length') || errorMessage.includes('Script execution timed out')) {
        if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
          challengeUtils.solve(challenges.yamlBombChallenge)
        }
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
      } else {
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
      }
    }
  } else {
    res.status(410)
    next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
  }
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
