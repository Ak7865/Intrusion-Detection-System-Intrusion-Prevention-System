/** @type {import('next').NextConfig} */
module.exports = {
  reactStrictMode: true,
  env: {
    // Backend URL used by the Next.js API proxy route.
    // Override with IPS_API_URL environment variable if the backend is on a different host.
    IPS_API_URL: process.env.IPS_API_URL || "http://192.168.56.1:8765",
  },
};
