// API Configuration
// In production (GitHub Pages), point to Render backend
// In local dev, uses Vite proxy (empty string = same origin)
const PRODUCTION_API = 'https://agentpay-backend.onrender.com'
export const API_BASE_URL = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? PRODUCTION_API : '')
