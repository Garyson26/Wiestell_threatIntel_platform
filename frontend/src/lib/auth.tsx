'use client';

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { getMe } from '@/lib/api';
import { clearUserActivities } from '@/lib/userActivity';
import type { UserProfile } from '@/lib/types';

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  login: (token: string, user: UserProfile) => void;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  login: () => {},
  logout: () => {},
  loading: true,
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const saved = localStorage.getItem('sentinel_token');
    if (saved) {
      setToken(saved);
      getMe()
        .then((u) => setUser(u))
        .catch(() => {
          localStorage.removeItem('sentinel_token');
          setToken(null);
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = useCallback((newToken: string, newUser: UserProfile) => {
    localStorage.setItem('sentinel_token', newToken);
    setToken(newToken);
    setUser(newUser);
  }, []);

  const logout = useCallback(() => {
    // Locally cached IOC activity is per-user analyst history; it must not
    // survive logout for the next person to use this browser.
    if (user?.id) {
      clearUserActivities(user.id);
    }
    localStorage.removeItem('sentinel_token');
    setToken(null);
    setUser(null);
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
