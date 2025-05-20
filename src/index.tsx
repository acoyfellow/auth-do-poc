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

// --- WebCrypto password hashing ---
async function hashPassword(password: string): Promise<{ hash: string; salt: string }> {
  const encoder = new TextEncoder();
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = btoa(String.fromCharCode(...saltBytes));

  const key = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: 100_000, hash: 'SHA-256' }, key, 256);
  const hash = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
  console.log('Hashing password:', { salt, hash });
  return { hash, salt };
}

async function verifyPassword(password: string, salt: string, expectedHash: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: 100_000, hash: 'SHA-256' }, key, 256);
  const hash = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
  console.log('Verifying password:', {
    providedSalt: salt,
    providedHash: expectedHash,
    computedHash: hash,
    matches: hash === expectedHash
  });
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

const Layout = (props: { children: any }) => (
  <html>
    <head><title>Auth POC</title></head>
    <body style={{ padding: '2rem', fontFamily: 'sans-serif' }}>{props.children}</body>
  </html>
);

// --- Signup ---
app.get('/signup', (c) => {
  return c.html(
    <Layout>
      <h1>Sign Up</h1>
      <form method="post" action="/signup">
        <input name="email" type="email" placeholder="email" required /><br />
        <input name="password" type="password" placeholder="password" required /><br />
        <button type="submit">Create account</button>
      </form>
      <a href="/login">Already have an account?</a>
    </Layout>
  );
});

app.post('/signup', async (c) => {
  const form = await c.req.parseBody();
  const email = form['email']?.toString() ?? '';
  const password = form['password']?.toString() ?? '';
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

  const token = sign({ id }, c.env.JWT_SECRET, { expiresIn: '7d' });
  setCookie(c, 'auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 7 * 24 * 60 * 60, // 7 days in seconds
    path: '/'
  });
  return c.redirect('/');
});

// --- Login ---
app.get('/login', (c) => {
  return c.html(
    <Layout>
      <h1>Login</h1>
      <form method="post" action="/login">
        <input name="email" type="email" placeholder="email" required /><br />
        <input name="password" type="password" placeholder="password" required /><br />
        <button type="submit">Login</button>
      </form>
      <a href="/signup">Create account</a>
    </Layout>
  );
});

app.post('/login', async (c) => {
  const form = await c.req.parseBody();
  const email = form['email']?.toString() ?? '';
  const password = form['password']?.toString() ?? '';

  // Get user DO by email
  const userStub = c.env.USER_DO.get(c.env.USER_DO.idFromName(email));
  const resp = await userStub.fetch('http://do/raw');
  if (resp.status !== 200) {
    console.log('User not found for email:', email);
    return c.text('Invalid credentials', 401);
  }

  const user = await resp.json<User>();
  if (!user || !user.email) {
    console.log('Invalid user data for email:', email);
    return c.text('Invalid credentials', 401);
  }

  // Verify password
  const ok = await verifyPassword(password, user.salt, user.passwordHash);
  if (!ok) {
    console.log('Password verification failed for user:', user.email);
    return c.text('Invalid credentials', 401);
  }

  const token = sign({ id: user.id }, c.env.JWT_SECRET, { expiresIn: '7d' });
  setCookie(c, 'auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 7 * 24 * 60 * 60, // 7 days in seconds
    path: '/'
  });
  return c.redirect('/');
});

// --- Logout ---
app.post('/logout', (c) => {
  deleteCookie(c, 'auth_token');
  return c.redirect('/login');
});

// --- Protected route ---
app.get('/', async (c) => {
  const token = getCookie(c, 'auth_token');
  if (!token) {
    console.log('No auth token found');
    return c.redirect('/login');
  }

  let decoded: any;
  try {
    decoded = verify(token, c.env.JWT_SECRET);
    console.log('Decoded token:', decoded);
  } catch (e) {
    console.log('Token verification failed:', e);
    deleteCookie(c, 'auth_token');
    return c.redirect('/login');
  }

  const stub = c.env.USER_DO.get(c.env.USER_DO.idFromName(decoded.id));
  const resp = await stub.fetch('http://do/meta');
  if (resp.status !== 200) {
    console.log('User not found for ID:', decoded.id);
    deleteCookie(c, 'auth_token');
    return c.redirect('/login');
  }

  const user = await resp.json<Omit<User, 'passwordHash' | 'salt'>>();
  console.log('Found user:', user);

  return c.html(
    <Layout>
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
