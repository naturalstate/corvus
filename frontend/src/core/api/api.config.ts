// ===================
// ©AngelaMos | 2026
// api.config.ts
// ===================

import axios, { type AxiosError, type AxiosInstance } from 'axios'
import { transformAxiosError } from './errors'

const getBaseURL = (): string => {
  return import.meta.env.VITE_API_URL ?? '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

// Normalise every transport failure into the typed ApiError the query client's
// retry and toast policy is written against, reading the server's `{error}`
// body for the message it carries.
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => Promise.reject(transformAxiosError(error))
)
