// ===================
// ©AngelaMos | 2026
// routers.tsx
// ===================

import { createBrowserRouter, type RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    path: ROUTES.HOME,
    lazy: () => import('@/pages/landing'),
  },
  {
    element: <Shell />,
    children: [
      {
        path: ROUTES.SCOPE,
        lazy: () => import('@/pages/scope'),
      },
      {
        path: ROUTES.INTEL,
        lazy: () => import('@/pages/intel'),
      },
    ],
  },
  {
    path: '*',
    lazy: () => import('@/pages/landing'),
  },
]

export const router = createBrowserRouter(routes)
