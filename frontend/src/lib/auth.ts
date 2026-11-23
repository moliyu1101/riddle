const TOKEN_KEY = "riddle_console_token";
const RIDDLE_TOKEN_KEY = "riddle_token";
const LOGOUT_KEY = "riddle_logged_out";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 天（秒）
// Standard 3-segment local operator payload ({"alg":"none"}.{"sub":"Riddle"}.local) for keyless local startup.
const DEFAULT_LOCAL_TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJSaWRkbGUifQ.local";

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    const saved = localStorage.getItem(TOKEN_KEY) ?? localStorage.getItem(RIDDLE_TOKEN_KEY);
    if (saved) return saved;
    if (localStorage.getItem(LOGOUT_KEY) === "1") return null;
    return DEFAULT_LOCAL_TOKEN;
  },

  setToken(token: string): void {
    localStorage.removeItem(LOGOUT_KEY);
    localStorage.setItem(TOKEN_KEY, token);
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
    if (!token.endsWith(".local")) {
      localStorage.setItem(RIDDLE_TOKEN_KEY, token);
      document.cookie = `${RIDDLE_TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
    }
  },

  clearToken(explicitLogout = false): void {
    if (explicitLogout) {
      localStorage.setItem(LOGOUT_KEY, "1");
    }
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(RIDDLE_TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
    document.cookie = `${RIDDLE_TOKEN_KEY}=; path=/; max-age=0`;
  },

  // 从 JWT payload 的 sub 字段解析当前用户，仅用于展示，不做签名验证。
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return { id: "1", name: "Riddle", username: "Riddle", email: "", avatar: "", role: "operator" };
      }
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "Riddle";
      return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
    } catch {
      return { id: "1", name: "Riddle", username: "Riddle", email: "", avatar: "", role: "operator" };
    }
  },
};
