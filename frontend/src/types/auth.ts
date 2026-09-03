/** Mirrors backend/models/schemas.py::AuthStatusResponse / LoginRequest /
 * RegisterRequest / UserPublicResponse exactly. */

export interface LoginRequest {
  username: string;
  password: string;
}

export interface AuthStatusResponse {
  authenticated: boolean;
  username: string | null;
  /** "demo" for the env-credential bootstrap login, the user's database id (as a
   * string) for a registered account, or null when unauthenticated. */
  user_id: string | null;
}

export interface RegisterRequest {
  username: string;
  password: string;
}

export interface UserPublic {
  id: string;
  username: string;
  created_at: string;
}
