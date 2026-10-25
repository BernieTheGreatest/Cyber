/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { crc32 } from 'node:zlib'
import { extractZipBuffer } from '../../routes/fileUpload'
import { parseXmlString } from '../../lib/xml'

function archive (name: string, body = 'ordinary complaint', mode = 0o100644) {
  const filename = Buffer.from(name)
  const data = Buffer.from(body)
  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50)
  local.writeUInt16LE(20, 4)
  local.writeUInt32LE(crc32(data), 14)
  local.writeUInt32LE(data.length, 18)
  local.writeUInt32LE(data.length, 22)
  local.writeUInt16LE(filename.length, 26)
  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50)
  central.writeUInt16LE(0x0314, 4)
  central.writeUInt16LE(20, 6)
  central.writeUInt32LE(crc32(data), 16)
  central.writeUInt32LE(data.length, 20)
  central.writeUInt32LE(data.length, 24)
  central.writeUInt16LE(filename.length, 28)
  central.writeUInt32LE((mode << 16) >>> 0, 38)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50)
  end.writeUInt16LE(1, 8)
  end.writeUInt16LE(1, 10)
  end.writeUInt32LE(central.length + filename.length, 12)
  end.writeUInt32LE(local.length + filename.length + data.length, 16)
  return Buffer.concat([local, filename, data, central, filename, end])
}

void describe('production file boundaries', () => {
  void it('extracts ordinary files and rejects traversal, absolute paths, symlinks and overwrites', async () => {
    const original = process.cwd()
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'juice-security-'))
    try {
      process.chdir(temporary)
      await extractZipBuffer(archive('nested/complaint.txt'))
      assert.equal(await fs.readFile('uploads/complaints/nested/complaint.txt', 'utf8'), 'ordinary complaint')
      for (const name of ['../../sentinel.txt', '/tmp/sentinel.txt', 'C:\\sentinel.txt', '..\\sentinel.txt']) {
        await assert.rejects(extractZipBuffer(archive(name)), /Invalid archive path/)
      }
      await assert.rejects(extractZipBuffer(archive('link', '/tmp', 0o120777)), /Invalid archive path/)
      await assert.rejects(extractZipBuffer(archive('nested/complaint.txt', 'overwrite')), /EEXIST/)
      assert.equal(await fs.readFile('uploads/complaints/nested/complaint.txt', 'utf8'), 'ordinary complaint')
      await assert.rejects(fs.access('sentinel.txt'))
    } finally {
      process.chdir(original)
      await fs.rm(temporary, { recursive: true, force: true })
    }
  })
  void it('rejects external entities while retaining ordinary XML parsing', async () => {
    for (const declaration of ['<!DOCTYPE r SYSTEM "file:///etc/passwd">', '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]>']) {
      await assert.rejects(parseXmlString(`${declaration}<r>&e;</r>`), /DTD and entity/)
    }
    assert.match(await parseXmlString('<r>ordinary &amp; safe</r>'), /ordinary &amp; safe/)
  })
})
