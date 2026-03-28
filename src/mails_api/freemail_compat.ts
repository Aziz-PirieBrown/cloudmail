import { Hono } from "hono"

import { commonParseMail, newAddress } from "../common"
import { getAdminPasswords, getDefaultDomains } from "../utils"

export const api = new Hono<HonoCustomType>()

const OTP_REGEX = /\b\d{6}\b/

function getAdminTokenCandidates(c: any): string[] {
    const tokens = new Set<string>()
    if (c.env.FREEMAIL_ADMIN_TOKEN) tokens.add(c.env.FREEMAIL_ADMIN_TOKEN)
    if (c.env.JWT_SECRET) tokens.add(c.env.JWT_SECRET)
    for (const value of getAdminPasswords(c)) {
        if (value) tokens.add(value)
    }
    return [...tokens]
}

function readBearerToken(headerValue: string | undefined | null): string {
    if (!headerValue) return ""
    const trimmed = headerValue.trim()
    if (trimmed.toLowerCase().startsWith("bearer ")) {
        return trimmed.slice(7).trim()
    }
    return trimmed
}

function ensureAdminAuth(c: any): Response | undefined {
    const provided = readBearerToken(c.req.header("Authorization"))
    const expected = getAdminTokenCandidates(c)
    if (provided && expected.includes(provided)) return undefined

    const adminHeader = c.req.header("x-admin-auth")
    if (adminHeader && getAdminPasswords(c).includes(adminHeader)) return undefined

    return c.json({ error: "Unauthorized" }, 401)
}

function getDomainsForCompat(c: any): string[] {
    return getDefaultDomains(c)
}

function randomLocal(length: number): string {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    let out = ""
    for (let i = 0; i < length; i += 1) {
        out += chars[Math.floor(Math.random() * chars.length)]
    }
    return out
}

function extractVerificationCode(content: string): string | null {
    const match = content.match(OTP_REGEX)
    return match ? match[0] : null
}

async function purgeHistoricalMailboxData(c: any, address: string, addressId: number): Promise<void> {
    await c.env.DB.prepare(
        `DELETE FROM raw_mails WHERE address = ? AND created_at < (SELECT created_at FROM address WHERE id = ?)`
    ).bind(address, addressId).run()
}

api.use('/api/*', async (c, next) => {
    const authResponse = ensureAdminAuth(c)
    if (authResponse) return authResponse
    await next()
})

api.get('/api/domains', (c) => {
    return c.json(getDomainsForCompat(c))
})

api.post('/api/create', async (c) => {
    const domains = getDomainsForCompat(c)
    const body = await c.req.json().catch(() => ({}))
    const domainIndex = Math.max(0, Number(body?.domainIndex) || 0)
    const domain = domains[domainIndex] || domains[0]
    const local = String(body?.local || '').trim()
    if (!domain) return c.json({ error: 'No domains configured' }, 400)
    if (!local) return c.json({ error: 'Missing local part' }, 400)

    const result = await newAddress(c, {
        name: local,
        domain,
        enablePrefix: false,
        checkLengthByConfig: false,
        checkAllowDomains: false,
        enableCheckNameRegex: false,
        sourceMeta: 'freemail:compat',
    })

    await purgeHistoricalMailboxData(c, result.address, result.address_id)

    return c.json({
        email: result.address,
        id: result.address,
        service_id: result.address,
        jwt: result.jwt,
        address_id: result.address_id,
    })
})

api.get('/api/generate', async (c) => {
    const domains = getDomainsForCompat(c)
    const query = c.req.query()
    const domainIndex = Math.max(0, Number(query.domainIndex) || 0)
    const domain = domains[domainIndex] || domains[0]
    const requestedLength = Number(query.length) || 10
    const length = Math.min(Math.max(requestedLength, 6), 24)
    if (!domain) return c.json({ error: 'No domains configured' }, 400)

    const result = await newAddress(c, {
        name: randomLocal(length),
        domain,
        enablePrefix: false,
        checkLengthByConfig: false,
        checkAllowDomains: false,
        enableCheckNameRegex: false,
        sourceMeta: 'freemail:compat',
    })

    await purgeHistoricalMailboxData(c, result.address, result.address_id)

    return c.json({
        email: result.address,
        id: result.address,
        service_id: result.address,
        jwt: result.jwt,
        address_id: result.address_id,
    })
})

api.get('/api/emails', async (c) => {
    const mailbox = String(c.req.query('mailbox') || '').trim().toLowerCase()
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 20, 1), 100)
    if (!mailbox) return c.json({ error: 'Missing mailbox' }, 400)

    const mailboxCreatedAt = await c.env.DB.prepare(
        'SELECT created_at FROM address WHERE name = ?'
    ).bind(mailbox).first<string>('created_at')

    const { results } = await c.env.DB.prepare(
        'SELECT id, source, address, raw, message_id, created_at FROM raw_mails WHERE address = ? AND created_at >= COALESCE(?, created_at) ORDER BY id DESC LIMIT ?'
    ).bind(mailbox, mailboxCreatedAt, limit).all()

    const mails = []
    for (const row of (results || [])) {
        const parsed = await commonParseMail({ rawEmail: row.raw })
        const text = parsed?.text || ''
        const subject = parsed?.subject || ''
        const preview = (text || subject || '').replace(/\s+/g, ' ').trim().slice(0, 200)
        mails.push({
            id: row.id,
            sender: parsed?.sender || row.source || '',
            subject,
            preview,
            created_at: row.created_at,
            message_id: row.message_id || '',
            verification_code: extractVerificationCode(`${subject}\n${text}`) || '',
        })
    }

    return c.json(mails)
})

api.get('/api/email/:mail_id', async (c) => {
    const mailId = Number(c.req.param('mail_id'))
    if (!mailId) return c.json({ error: 'Invalid mail id' }, 400)

    const row = await c.env.DB.prepare(
        'SELECT id, source, address, raw, message_id, created_at FROM raw_mails WHERE id = ?'
    ).bind(mailId).first<any>()
    if (!row) return c.json({ error: 'Mail not found' }, 404)

    const parsed = await commonParseMail({ rawEmail: row.raw })
    const text = parsed?.text || ''
    const html = parsed?.html || ''
    const subject = parsed?.subject || ''

    return c.json({
        id: row.id,
        sender: parsed?.sender || row.source || '',
        subject,
        content: text,
        html_content: html,
        text_content: text,
        message_id: row.message_id || '',
        created_at: row.created_at,
        verification_code: extractVerificationCode(`${subject}\n${text}`) || '',
    })
})

api.get('/api/mailboxes', async (c) => {
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 100, 1), 500)
    const offset = Math.max(Number(c.req.query('offset')) || 0, 0)
    const { results } = await c.env.DB.prepare(
        'SELECT id, name, created_at, updated_at FROM address ORDER BY id DESC LIMIT ? OFFSET ?'
    ).bind(limit, offset).all()

    return c.json((results || []).map((row: any) => ({
        id: row.name,
        address: row.name,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })))
})

api.delete('/api/mailboxes', async (c) => {
    const address = String(c.req.query('address') || '').trim().toLowerCase()
    if (!address) return c.json({ error: 'Missing address' }, 400)

    const addressId = await c.env.DB.prepare('SELECT id FROM address WHERE name = ?').bind(address).first<number>('id')
    if (!addressId) return c.json({ success: true, deleted: false })

    await c.env.DB.prepare('DELETE FROM raw_mails WHERE address = ?').bind(address).run()
    await c.env.DB.prepare('DELETE FROM sendbox WHERE address = ?').bind(address).run()
    await c.env.DB.prepare('DELETE FROM auto_reply_mails WHERE address = ?').bind(address).run()
    await c.env.DB.prepare('DELETE FROM address_sender WHERE address = ?').bind(address).run()
    await c.env.DB.prepare('DELETE FROM users_address WHERE address_id = ?').bind(addressId).run()
    await c.env.DB.prepare('DELETE FROM address WHERE id = ?').bind(addressId).run()

    return c.json({ success: true, deleted: true })
})
