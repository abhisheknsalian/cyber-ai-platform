import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";

import {
  getAuthStatus,
  login as apiLogin,
  logout as apiLogout,
  register as apiRegister,
  UNAUTHORIZED_EVENT,
} from "../services/api";
import type { LoginRequest, RegisterRequest, UserPublic } from "../types/auth";

interface AuthContextValue {
  /** True once the initial GET /auth/me check has completed (success or failure) --
   * used to avoid flashing the login page before we actually know the status. */
  ready: boolean;
  authenticated: boolean;
  username: string | null;
  userId: string | null;
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
  /** Creates a new account. Does NOT log the user in -- callers navigate to the
   * login page on success, matching the target registration flow. */
  register: (payload: RegisterRequest) => Promise<UserPublic>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getAuthStatus()
      .then((status) => {
        if (cancelled) return;
        setAuthenticated(status.authenticated);
        setUsername(status.username);
        setUserId(status.user_id);
      })
      .catch(() => {
        if (cancelled) return;
        setAuthenticated(false);
        setUsername(null);
        setUserId(null);
      })
      .finally(() => {
        if (!cancelled) setReady(true);
      });

    function handleUnauthorized() {
      setAuthenticated(false);
      setUsername(null);
      setUserId(null);
    }

    window.addEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    return () => {
      cancelled = true;
      window.removeEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    };
  }, []);

  async function login(credentials: LoginRequest) {
    // Let ApiError propagate -- LoginPage owns displaying the failure message,
    // matching how every other page in this app handles its own request errors.
    const status = await apiLogin(credentials);
    setAuthenticated(status.authenticated);
    setUsername(status.username);
    setUserId(status.user_id);
  }

  async function logout() {
    try {
      await apiLogout();
    } finally {
      // Drop to the login state locally even if the request itself failed (e.g.
      // backend briefly unreachable) -- there's nothing else productive to do.
      setAuthenticated(false);
      setUsername(null);
      setUserId(null);
    }
  }

  async function register(payload: RegisterRequest) {
    // Let ApiError propagate -- RegisterPage owns displaying the failure message,
    // same convention as login() above. Deliberately does not touch auth state:
    // registering an account does not log the user in.
    return apiRegister(payload);
  }

  return (
    <AuthContext.Provider value={{ ready, authenticated, username, userId, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
