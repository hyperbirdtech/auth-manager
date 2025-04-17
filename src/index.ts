import { Request, Response, NextFunction } from "express";
import { v4 as uuidv4 } from "uuid";
import Memcached from "memcached";
import rateLimit from "express-rate-limit";
import type { RequestHandler } from "express";

export class AuthManager {
  private strategies = new Map<string, AuthStrategy>();
  private sessionAdapter?: SessionAdapter;

  useStrategy(strategy: AuthStrategy): this {
    this.strategies.set(strategy.name, strategy);
    return this;
  }

  setSessionAdapter(adapter: SessionAdapter): this {
    this.sessionAdapter = adapter;
    return this;
  }

  async login<TPayload>(
    strategyName: string,
    payload: TPayload
  ): Promise<string> {
    const strategy = this.strategies.get(strategyName);
    if (!strategy) throw new Error(`Strategy '${strategyName}' not found`);

    const user = await strategy.validate(payload as LoginPayload);
    if (!this.sessionAdapter) throw new Error("Session adapter not set");

    return this.sessionAdapter.create(user);
  }

  async authenticate(sessionId: string): Promise<AuthUser | null> {
    if (!this.sessionAdapter) throw new Error("Session adapter not set");
    return this.sessionAdapter.get(sessionId);
  }

  async logout(sessionId: string): Promise<void> {
    if (!this.sessionAdapter) throw new Error("Session adapter not set");
    return this.sessionAdapter.destroy(sessionId);
  }
}

export function withAuth(auth: AuthManager, cookieKey: string = "sessionId") {
  return async function (req: Request, res: Response, next: NextFunction) {
    const sessionId = req.cookies?.[cookieKey];
    if (!sessionId) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const user = await auth.authenticate(sessionId);
    if (!user) {
      return res.status(401).json({ error: "Invalid session" });
    }
    (req as any).user = user;
    next();
  };
}

export interface PasswordStrategyOptions {
  name?: string;
  findUserByEmail(email: string): Promise<AuthUser | null>;
  comparePasswords(input: string, stored: string): boolean;
}

export class PasswordStrategy
  implements AuthStrategy<{ email: string; password: string }>
{
  name: string;
  private findUserByEmail: PasswordStrategyOptions["findUserByEmail"];
  private comparePasswords: PasswordStrategyOptions["comparePasswords"];

  constructor(options: PasswordStrategyOptions) {
    this.name = options.name || "password";
    this.findUserByEmail = options.findUserByEmail;
    this.comparePasswords = options.comparePasswords;
  }

  async validate(payload: {
    email: string;
    password: string;
  }): Promise<AuthUser> {
    const user = await this.findUserByEmail(payload.email);
    if (!user || !this.comparePasswords(payload.password, user.password)) {
      throw new Error("Invalid credentials");
    }
    return user;
  }
}

export function withRateLimit(
  options?: Partial<typeof rateLimit>
): RequestHandler {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: "Too many requests, please try again later.",
    ...options,
  });
}

export class MemcachedSessionAdapter implements SessionAdapter {
  constructor(private client: Memcached, private ttl: number = 3600) {}

  async create(user: AuthUser): Promise<string> {
    const sessionId = uuidv4();
    return new Promise((resolve, reject) => {
      this.client.set(sessionId, user, this.ttl, (err) => {
        if (err) reject(err);
        else resolve(sessionId);
      });
    });
  }

  async get(sessionId: string): Promise<AuthUser | null> {
    return new Promise((resolve, reject) => {
      this.client.get(sessionId, (err, data) => {
        if (err) return reject(err);
        resolve(data || null);
      });
    });
  }

  async destroy(sessionId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.client.del(sessionId, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}
