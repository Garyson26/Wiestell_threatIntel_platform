'use client';

import RoleBasedRoute from './RoleBasedRoute';

interface AdminRouteProps {
  children: React.ReactNode;
}

export default function AdminRoute({ children }: AdminRouteProps) {
  return (
    <RoleBasedRoute allowedRoles={['admin']}>
      {children}
    </RoleBasedRoute>
  );
}
