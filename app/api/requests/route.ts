import { adminAuth, adminFirestore } from '@/utils/firebase'
import {
  decrypt,
  encrypt,
  encryptedFields,
  validateData,
} from '@/utils/helpers'
import { cloneDeep } from 'lodash'
import createDOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

export async function GET(request: Request) {
  try {
    const apiKey = request.headers.get('Authorization')?.split('Bearer ')[1]

    const userUid = await adminAuth
      .verifyIdToken(String(apiKey))
      .then((decodedToken) => decodedToken.uid)
      .catch(() => {
        return null
      })

    const userDoc = (
      await adminFirestore
        .collection('users')
        .doc(userUid || '')
        .get()
    ).data()

    const isAdmin = userDoc?.role === 'Admin'

    if (!apiKey || !userUid || !isAdmin) {
      return new Response('Unauthorized', { status: 401 })
    }

    const collectionRef = adminFirestore.collection('requests')
    const data = await collectionRef.get().then((snapshot) => {
      const documents: { id: string; data: FirebaseFirestore.DocumentData }[] =
        []
      snapshot.forEach((doc) => {
        const encryptedFields = ['fullName', 'email', 'phoneNumber', 'postcode']
        const docData = cloneDeep(doc.data())

        Object.keys(docData).forEach((key: string) => {
          if (
            typeof docData[key] !== 'string' &&
            encryptedFields.includes(key)
          ) {
            docData[key] = decrypt(docData[key])
          }
        })
        documents.push({
          id: doc.id,
          data: docData,
        })
      })
      return documents
    })

    return Response.json(data)
  } catch (error) {
    return new Response('Internal Server Error', { status: 500 })
  }
}

const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window)

export async function POST(request: Request) {
  try {
    const apiKey = request.headers.get('Authorization')?.split('Bearer ')[1]

    if (!apiKey) {
      return new Response('Unauthorized', { status: 401 })
    }

    const userUid = await adminAuth
      .verifyIdToken(String(apiKey))
      .then((decodedToken) => decodedToken.uid)
      .catch(() => {
        return null
      })

    if (!userUid) {
      return new Response('Unauthorized', { status: 401 })
    }

    const userDoc = await adminFirestore
      .collection('users')
      .doc(userUid || '')
      .get()

    const isAdmin = userDoc.exists && userDoc?.data()?.role === 'Admin'

    if (!isAdmin) {
      return new Response('Forbidden', { status: 403 })
    }

    const requestData = await request.json()
    const validData = validateData(requestData)

    if (!validData) {
      return new Response('Invalid Data', { status: 400 })
    }

    const formDataClone = cloneDeep(validData)
    const processedData = Object.fromEntries(
      Object.entries(formDataClone).map(([key, value]) => {
        if (typeof value !== 'boolean') {
          const sanitizedValue = value
            ? DOMPurify.sanitize(value, {
                FORBID_TAGS: ['a'],
                KEEP_CONTENT: false,
              })
            : ''

          const newValue = encryptedFields.includes(key)
            ? encrypt(String(sanitizedValue))
            : sanitizedValue

          return [key, newValue]
        } else {
          return [key, value ?? '']
        }
      })
    )

    const collectionRef = adminFirestore.collection('requests')
    const docRef = await collectionRef.add({
      ...processedData,
      submittedAt: new Date(),
    })

    const newDoc = await docRef.get()

    return Response.json({ id: newDoc.id, data: newDoc.data() })
  } catch (error) {
    return new Response('Internal Server Error', { status: 500 })
  }
}
