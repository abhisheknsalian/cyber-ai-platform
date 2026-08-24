/** Mirrors backend/models/schemas.py::AuthStatusResponse / LoginRequest exactly. */

export interface LoginRequest {
  username: string;
  password: string;
}

export interface AuthStatusResponse {
  authenticated: boolean;
  username: string | null;
}
