import * as crypto from 'crypto'
import { z } from 'zod'

const algorithm = 'aes-256-ctr'
const secretKey = Buffer.from(String(process.env.SECRET_KEY), 'hex')

export const encrypt = (text: string) => {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv)
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()])
  return {
    iv: iv.toString('hex'),
    content: encrypted.toString('hex'),
  }
}

export const decrypt = (hash: any) => {
  const decipher = crypto.createDecipheriv(
    algorithm,
    secretKey,
    Buffer.from(String(hash.iv), 'hex')
  )
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(hash.content, 'hex')),
    decipher.final(),
  ])
  return decrypted.toString()
}

export const encryptedFields = ['fullName', 'email', 'phoneNumber', 'postcode']

const StatusValues = [
  'awaitingQuote',
  'quoteSent',
  'quoteAccepted',
  'quoteRejected',
  'jobAccepted',
] as const
export const inputDataSchema = z.object({
  fullName: z
    .string()
    .min(1, 'Full name is required')
    .max(100, 'Full name must be less than 100 characters'),
  email: z.string().email('Invalid email address'),
  phoneNumber: z.string().regex(/^(?:\+44|0)7\d{9}$/, 'Invalid phone number'),
  postcode: z
    .string()
    .regex(/^[A-Z]{1,2}[0-9R][0-9A-Z]?[ ]?[0-9][A-Z]{2}$/i, 'Invalid postcode'),
  cleaningType: z.string().min(1, 'Cleaning type is required'),
  serviceLevel: z.string().min(1, 'Service level is required'),
  rooms: z.preprocess((value) => {
    if (typeof value === 'number') {
      return String(value)
    }
    return value
  }, z.string().max(2).regex(/^\d+$/, 'Rooms must contain only numeric characters')),
  bathrooms: z.preprocess((value) => {
    if (typeof value === 'number') {
      return String(value)
    }
    return value
  }, z.string().max(2).regex(/^\d+$/, 'Bathrooms must contain only numeric characters')),
  kitchens: z.preprocess((value) => {
    if (typeof value === 'number') {
      return String(value)
    }
    return value
  }, z.string().max(2).regex(/^\d+$/, 'Kitchens must contain only numeric characters')),
  ovenCleaning: z.boolean().optional(),
  additionalInfo: z.string().optional(),
  status: z.enum(StatusValues),
})

type InputData = z.infer<typeof inputDataSchema>

export const validateData = (data: InputData) => {
  const result = inputDataSchema.safeParse(data)

  if (!result.success) {
    return null
  }

  return result.data
}
