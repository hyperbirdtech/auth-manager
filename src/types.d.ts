type AuthUser = {
  id: string;
  email: string;
  [key: string]: any;
};

type LoginPayload = {
  [key: string]: any;
};

type AuthStrategy<TPayload = LoginPayload> = {
  name: string;
  validate(payload: TPayload): Promise<AuthUser>;
};

type SessionAdapter = {
  create(user: AuthUser): Promise<string>; // returns sessionId
  get(sessionId: string): Promise<AuthUser | null>;
  destroy(sessionId: string): Promise<void>;
};
