import type { Metadata } from "next"
import { Inter } from "next/font/google"

import { ConsoleProvider } from "@/components/console/console-context"
import "./globals.css"
import { Providers } from "./providers"

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
})

export const metadata: Metadata = {
  title: "rscale Console",
  description:
    "rscale is an independent, self-hosted Rust control plane compatible with Tailscale clients and not affiliated with Tailscale Inc. or the headscale project.",
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
    shortcut: [
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="zh-CN"
      suppressHydrationWarning
      className={inter.variable}
    >
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        <Providers>
          <ConsoleProvider>{children}</ConsoleProvider>
        </Providers>
      </body>
    </html>
  )
}
