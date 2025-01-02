import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  /* config options here */
  async headers() {
    const allowedOrigin = process.env.NEXT_PUBLIC_ALLOWED_ORIGIN

    if (!allowedOrigin) {
      console.error('Allowed origin is not set in the environment variable')
      return []
    }
    return [
      {
        source: '/api/:path*',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: allowedOrigin,
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET, POST, PUT, DELETE, OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value: 'Content-Type, Authorization',
          },
        ],
      },
    ]
  },
}

export default nextConfig
