import { adminAuth, adminFirestore } from '@/utils/firebase'
import { decrypt, encryptedFields } from '@/utils/helpers'
import { cloneDeep } from 'lodash'

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const id = (await params).id
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
    const data = await collectionRef
      .doc(id)
      .get()
      .then((doc) => {
        const docData = cloneDeep(doc.data())
        if (docData) {
          Object.keys(docData).forEach((key: string) => {
            if (
              typeof docData[key] !== 'string' &&
              encryptedFields.includes(key)
            ) {
              docData[key] = decrypt(docData[key])
            }
          })
        }
        return docData
      })

    return Response.json(data)
  } catch (error) {
    return new Response('Internal Server Error', { status: 500 })
  }
}
