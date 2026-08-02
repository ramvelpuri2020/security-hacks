import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Security Scanner',
  description: 'Multi-stage security vulnerability scanner',
  generator: 'v0.app',
  icons: {
    icon: [
      {
        url: '/icon.svg',
        type: 'image/svg+xml',
      },
    ],
  },
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: [{ color: 'black' }],
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    // suppressHydrationWarning: browser extensions (e.g. session recorders) inject
    // attributes like `bis_register` onto <html>/<body> before React hydrates,
    // which triggers a hydration mismatch warning. This is safe to suppress.
    <html lang="en" className="dark bg-black" suppressHydrationWarning>
      <body className={`${inter.className} antialiased bg-black text-foreground`} style={{ '--font-mono': jetbrainsMono.style.fontFamily } as React.CSSProperties} suppressHydrationWarning>
        {children}
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
