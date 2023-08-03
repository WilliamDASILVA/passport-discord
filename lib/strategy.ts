import * as OAuth2 from 'passport-oauth2';
const { InternalOAuthError } = OAuth2

/**
 * Options for the Strategy.
 */
interface StrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope: Array<string>;
  authorizationURL?: string;
  tokenURL?: string;
  scopeSeparator?: string;
}

class Strategy extends OAuth2.Strategy {
  public name: string;
  public _oauth2: any
  public _scope: any

  constructor(options: StrategyOptions, verify: (accessToken: string, refreshToken: string, profile: any, done: (error: any, user?: any) => void) => void) {
    options.authorizationURL = options.authorizationURL || 'https://discord.com/api/oauth2/authorize';
    options.tokenURL = options.tokenURL || 'https://discord.com/api/oauth2/token';
    options.scopeSeparator = options.scopeSeparator || ' ';

    super(options as any, verify);
    this.name = 'discord';
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  userProfile(accessToken: string, done: (err: Error | null, profile?: any) => void): void {
    // @ts-ignore
    this._oauth2.get('https://discord.com/api/users/@me', accessToken, (err, body, res) => {
      if (err) {
        return done(new InternalOAuthError('Failed to fetch the user profile.', err));
      }

      let parsedData;
      try {
        parsedData = JSON.parse(body);
      } catch (e) {
        return done(new Error('Failed to parse the user profile.'));
      }

      const profile = parsedData;
      profile.provider = 'discord';
      profile.accessToken = accessToken;

      this.checkScope('connections', accessToken, (errx, connections) => {
        if (errx) done(errx);
        if (connections) profile.connections = connections;
        this.checkScope('guilds', accessToken, (erry, guilds) => {
          if (erry) done(erry);
          if (guilds) profile.guilds = guilds;

          profile.fetchedAt = new Date();
          return done(null, profile);
        });
      });
    });
  }

  checkScope(scope: string, accessToken: string, cb: (err: Error | null, json?: any) => void): void {
    if (this._scope && this._scope.indexOf(scope) !== -1) {
      // @ts-ignore
      this._oauth2.get(`https://discord.com/api/users/@me/${scope}`, accessToken, (err, body, res) => {
        if (err) return cb(new InternalOAuthError(`Failed to fetch user's ${scope}`, err));
        let json;
        try {
          json = JSON.parse(body);
        } catch (e) {
          return cb(new Error(`Failed to parse user's ${scope}`));
        }
        cb(null, json);
      });
    } else {
      cb(null, null);
    }
  }

  authorizationParams(options: { permissions?: any, prompt?: any }): { [key: string]: any } {
    const params: { [key: string]: any } = {};
    if (typeof options.permissions !== 'undefined') {
      params.permissions = options.permissions;
    }
    if (typeof options.prompt !== 'undefined') {
      params.prompt = options.prompt;
    }
    return params;
  }
}

export default Strategy
