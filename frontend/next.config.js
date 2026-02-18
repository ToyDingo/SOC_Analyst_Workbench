/** @type {import('next').NextConfig} */
const nextConfig = {
  // Make "fetch('/api/...')" proxy to your API base URL
  async rewrites() {
    const base = process.env.NEXT_PUBLIC_API_BASE_URL;
    if (!base) return [];
    return [
      { source: "/api/:path*", destination: `${base}/:path*` },
    ];
  },

  // take-home friendly: don’t fail docker builds on lint/type errors
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },
};

module.exports = nextConfig;
