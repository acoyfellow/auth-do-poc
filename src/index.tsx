/// <reference types="hono/jsx" />
import { Hono } from 'hono';
import {
  getCookie,
  setCookie,
  deleteCookie,
} from 'hono/cookie'
import { z } from 'zod';
import { sign, verify } from 'jsonwebtoken';
import { DurableObject } from "cloudflare:workers";

type Env = {
  JWT_SECRET: string;
  USER_DO: DurableObjectNamespace;
};

// JWT configuration
const JWT_CONFIG = {
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  refreshTokenExpirySeconds: 7 * 24 * 60 * 60,
};

// Rate limiting configuration
const RATE_LIMIT = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 5, // 5 attempts per window
};

// Password hashing configuration
const PASSWORD_CONFIG = {
  iterations: 310_000, // OWASP 2023 recommendation
  memorySize: 65536, // 64MB
  parallelism: 4,
  saltLength: 16,
};

// Rate limiting store
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const record = rateLimitStore.get(ip);

  if (!record) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_LIMIT.windowMs });
    return false;
  }

  if (now > record.resetTime) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_LIMIT.windowMs });
    return false;
  }

  if (record.count >= RATE_LIMIT.maxAttempts) {
    return true;
  }

  record.count++;
  return false;
}

// Generate CSRF token
function generateCSRFToken(): string {
  return crypto.randomUUID();
}

// Verify CSRF token
function verifyCSRFToken(token: string, storedToken: string): boolean {
  return token === storedToken;
}

// Generate token pair
function generateTokenPair(id: string, secret: string) {
  const accessToken = sign({ id }, secret, { expiresIn: JWT_CONFIG.accessTokenExpiry as any });
  const refreshToken = sign({ id, type: 'refresh' }, secret, { expiresIn: JWT_CONFIG.refreshTokenExpiry as any });
  return { accessToken, refreshToken };
}

// --- WebCrypto password hashing ---
async function hashPassword(password: string): Promise<{ hash: string; salt: string }> {
  const encoder = new TextEncoder();
  const saltBytes = crypto.getRandomValues(new Uint8Array(PASSWORD_CONFIG.saltLength));
  const salt = btoa(String.fromCharCode(...saltBytes));

  const key = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PASSWORD_CONFIG.iterations,
      hash: 'SHA-256'
    },
    key,
    256
  );
  const hash = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
  return { hash, salt };
}

async function verifyPassword(password: string, salt: string, expectedHash: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PASSWORD_CONFIG.iterations,
      hash: 'SHA-256'
    },
    key,
    256
  );
  const hash = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
  return hash === expectedHash;
}

// --- User Schema ---
const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  passwordHash: z.string(),
  salt: z.string(),
  createdAt: z.string(),
});

type User = z.infer<typeof UserSchema>;

// Password strength requirements
const PASSWORD_REQUIREMENTS = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
};

function validatePasswordStrength(password: string): { valid: boolean; message?: string } {
  if (password.length < PASSWORD_REQUIREMENTS.minLength) {
    return { valid: false, message: `Password must be at least ${PASSWORD_REQUIREMENTS.minLength} characters long` };
  }
  if (PASSWORD_REQUIREMENTS.requireUppercase && !/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  if (PASSWORD_REQUIREMENTS.requireLowercase && !/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  if (PASSWORD_REQUIREMENTS.requireNumbers && !/\d/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  if (PASSWORD_REQUIREMENTS.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character' };
  }
  return { valid: true };
}

// Generic error response
function errorResponse(c: any, status: number, message: string) {
  console.error(`Error (${status}): ${message}`);
  return c.text('An error occurred. Please try again later.', status);
}

// --- Durable Object per user ---
export class UserDO extends DurableObject {
  state: DurableObjectState;
  storage: DurableObjectStorage;
  app: Hono;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.state = state;
    this.storage = state.storage;
    this.app = new Hono();

    this.app.get('/meta', async (c) => {
      const data = await this.storage.get<User>('data');
      if (!data) return c.text('Not found', 404);
      const { passwordHash, salt, ...safe } = data;
      return c.json(safe);
    });

    this.app.post('/init', async (c) => {
      const user = await c.req.json();
      const parsed = UserSchema.safeParse(user);
      if (!parsed.success) return c.text('Invalid', 400);
      await this.storage.put('data', parsed.data);
      return c.text('OK');
    });

    this.app.get('/raw', async (c) => {
      const data = await this.storage.get<User>('data');
      return c.json(data || {});
    });

    this.app.get('/check-email', async (c) => {
      const data = await this.storage.get<User>('data');
      return c.json({ exists: !!data });
    });
  }

  fetch(request: Request) {
    return this.app.fetch(request);
  }
}

const app = new Hono<{ Bindings: Env }>();

const Layout = (props: { children: any; csrfToken?: string }) => (
  <html>
    <head>
      <title>Auth POC</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    </head>
    <body style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      {props.children}
      {props.csrfToken && <input type="hidden" name="_csrf" value={props.csrfToken} />}
    </body>
  </html>
);

// --- Signup ---
app.get('/signup', (c) => {
  const csrfToken = generateCSRFToken();
  setCookie(c, 'csrf_token', csrfToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 3600, // 1 hour
    path: '/'
  });

  return c.html(
    <Layout>
      <h1>Sign Up</h1>
      <form method="post" action="/signup">
        <input name="email" type="email" placeholder="email" required /><br />
        <input name="password" type="password" placeholder="password" required /><br />
        <input type="hidden" name="_csrf" value={csrfToken} />
        <button type="submit">Create account</button>
      </form>
      <a href="/login">Already have an account?</a>
    </Layout>
  );
});

app.post('/signup', async (c) => {
  try {
    const form = await c.req.parseBody();
    const csrfToken = getCookie(c, 'csrf_token');
    const formCsrfToken = form['_csrf']?.toString();
    if (!csrfToken || !formCsrfToken || !verifyCSRFToken(formCsrfToken, csrfToken)) {
      return errorResponse(c, 403, 'Invalid CSRF token');
    }
    const email = form['email']?.toString() ?? '';
    const password = form['password']?.toString() ?? '';

    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
      return c.text(passwordValidation.message!, 400);
    }

    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    // Check if user already exists
    const emailStub = c.env.USER_DO.get(c.env.USER_DO.idFromName(email));
    const checkResp = await emailStub.fetch('http://do/check-email');
    if (checkResp.status === 200) {
      const { exists } = await checkResp.json<{ exists: boolean }>();
      if (exists) {
        return c.text('Email already registered', 400);
      }
    }

    const { hash, salt } = await hashPassword(password);
    const userData = { id, email, passwordHash: hash, salt, createdAt };

    // Store in the user's DO (using email as the DO ID)
    await emailStub.fetch('http://do/init', {
      method: 'POST',
      body: JSON.stringify(userData)
    });

    // Also store in the ID-based DO for protected routes
    const idStub = c.env.USER_DO.get(c.env.USER_DO.idFromName(id));
    await idStub.fetch('http://do/init', {
      method: 'POST',
      body: JSON.stringify(userData)
    });

    const { accessToken, refreshToken } = generateTokenPair(id, c.env.JWT_SECRET);

    // Set access token
    setCookie(c, 'auth_token', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 900, // 15 minutes in seconds
      path: '/'
    });

    // Set refresh token
    setCookie(c, 'refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: JWT_CONFIG.refreshTokenExpirySeconds,
      path: '/'
    });

    return c.redirect('/');
  } catch (error) {
    return errorResponse(c, 500, 'Failed to create account');
  }
});

// --- Login ---
app.get('/login', (c) => {
  const csrfToken = generateCSRFToken();
  setCookie(c, 'csrf_token', csrfToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 3600, // 1 hour
    path: '/'
  });

  return c.html(
    <Layout>
      <h1>Login</h1>
      <form method="post" action="/login">
        <input name="email" type="email" placeholder="email" required /><br />
        <input name="password" type="password" placeholder="password" required /><br />
        <input type="hidden" name="_csrf" value={csrfToken} />
        <button type="submit">Login</button>
      </form>
      <a href="/signup">Create account</a>
    </Layout>
  );
});

app.post('/login', async (c) => {
  try {
    const ip = c.req.header('cf-connecting-ip') || 'unknown';
    if (isRateLimited(ip)) {
      return c.text('Too many login attempts. Please try again later.', 429);
    }
    const form = await c.req.parseBody();
    const csrfToken = getCookie(c, 'csrf_token');
    const formCsrfToken = form['_csrf']?.toString();
    if (!csrfToken || !formCsrfToken || !verifyCSRFToken(formCsrfToken, csrfToken)) {
      return errorResponse(c, 403, 'Invalid CSRF token');
    }
    const email = form['email']?.toString() ?? '';
    const password = form['password']?.toString() ?? '';

    // Get user DO by email
    const userStub = c.env.USER_DO.get(c.env.USER_DO.idFromName(email));
    const resp = await userStub.fetch('http://do/raw');
    if (resp.status !== 200) {
      return c.text('Invalid credentials', 401);
    }

    const user = await resp.json<User>();
    if (!user || !user.email) {
      return c.text('Invalid credentials', 401);
    }

    // Verify password
    const ok = await verifyPassword(password, user.salt, user.passwordHash);
    if (!ok) {
      return c.text('Invalid credentials', 401);
    }

    const { accessToken, refreshToken } = generateTokenPair(user.id, c.env.JWT_SECRET);

    // Set access token
    setCookie(c, 'auth_token', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 900, // 15 minutes in seconds
      path: '/'
    });

    // Set refresh token
    setCookie(c, 'refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: JWT_CONFIG.refreshTokenExpirySeconds,
      path: '/'
    });

    return c.redirect('/');
  } catch (error) {
    return errorResponse(c, 500, 'Failed to login');
  }
});

// --- Logout ---
app.post('/logout', (c) => {
  deleteCookie(c, 'auth_token');
  deleteCookie(c, 'refresh_token');
  deleteCookie(c, 'csrf_token');
  return c.redirect('/login');
});

// --- Refresh token endpoint ---
app.post('/refresh', async (c) => {
  try {
    const refreshToken = getCookie(c, 'refresh_token');
    if (!refreshToken) {
      return c.text('No refresh token', 401);
    }

    let decoded: any;
    try {
      decoded = verify(refreshToken, c.env.JWT_SECRET);
      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }
    } catch (e) {
      return c.text('Invalid refresh token', 401);
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokenPair(decoded.id, c.env.JWT_SECRET);

    // Set new access token
    setCookie(c, 'auth_token', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 900, // 15 minutes in seconds
      path: '/'
    });

    // Set new refresh token
    setCookie(c, 'refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: JWT_CONFIG.refreshTokenExpirySeconds,
      path: '/'
    });

    return c.text('OK');
  } catch (error) {
    return errorResponse(c, 500, 'Failed to refresh token');
  }
});

// --- Protected route ---
app.get('/', async (c) => {
  const token = getCookie(c, 'auth_token');
  if (!token) {
    return c.redirect('/login');
  }

  let decoded: any;
  try {
    decoded = verify(token, c.env.JWT_SECRET);
  } catch (e: any) {
    // If token is expired, try to refresh
    if (e.name === 'TokenExpiredError') {
      const refreshResp = await fetch(new Request(c.req.url, {
        method: 'POST',
        headers: c.req.header()
      }));
      if (refreshResp.ok) {
        return c.redirect('/');
      }
    }
    deleteCookie(c, 'auth_token');
    deleteCookie(c, 'refresh_token');
    return c.redirect('/login');
  }

  const stub = c.env.USER_DO.get(c.env.USER_DO.idFromName(decoded.id));
  const resp = await stub.fetch('http://do/meta');
  if (resp.status !== 200) {
    deleteCookie(c, 'auth_token');
    deleteCookie(c, 'refresh_token');
    return c.redirect('/login');
  }

  const user = await resp.json<Omit<User, 'passwordHash' | 'salt'>>();
  const csrfToken = generateCSRFToken();
  setCookie(c, 'csrf_token', csrfToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 3600, // 1 hour
    path: '/'
  });

  return c.html(
    <Layout csrfToken={csrfToken}>
      <h1>Welcome, {user.email}</h1>
      <p>User ID: {user.id}</p>
      <p>Created: {user.createdAt}</p>
      <form method="post" action="/logout">
        <button type="submit">Logout</button>
      </form>
    </Layout>
  );
});


export default app;
