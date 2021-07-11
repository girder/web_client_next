import axios_ from 'axios';
import cookies from 'js-cookie';
import { stringify } from 'qs';
import Vue from 'vue';

const GirderTokenLength = 64;
export const OauthTokenPrefix = '#girderToken=';
export const OauthTokenSuffix = '__';

// Girder's custom headers
const GirderToken = 'Girder-Token';
const GirderOtp = 'Girder-OTP';
const GirderAuthorization = 'Girder-Authorization';

function setCookieFromAuth(auth) {
  cookies.set('girderToken', auth.token, { expires: new Date(auth.expires) });
}

/**
 * set cookie if special string is found in the hash.
 * @param {Location} location
 */
function setCookieFromHash(location) {
  const arr = location.hash.split(OauthTokenPrefix);
  const tokenParts = arr[arr.length - 1].split(OauthTokenSuffix);
  let token = null;
  if (tokenParts.length >= 2) {
    // Both the prefix and the suffix were present
    [token] = tokenParts;
    location.hash = location.hash.replace(`${OauthTokenPrefix}${token}${OauthTokenSuffix}`, '');
  }
  if (token !== null && token.length === GirderTokenLength) {
    const expires = new Date();
    expires.setDate((new Date()).getDate() + 365);
    setCookieFromAuth({ token, expires });
  }
  return token;
}

/**
 * This is a subclass of axios that is meant to add Girder-specific helper functionality.
 */
export default class RestClient extends Vue {
  /**
   * @param {Object} [opts] Options for this instance.
   * @param {String} [opts.apiRoot="/api/v1"] The base path of the destination Girder's API
   *     (typically ending with "/api/v1").
   * @param {String} [opts.token] An initial value for the authentication token.
   * @param {Object} [opts.axios]  An axios instance to use for all requests.
   * @param {Boolean} [opts.authenticateWithCredentials=false] Whether to set `withCredentials` on
   *     authentication requests, capturing the cross-origin Girder-Token cookie for later XSRF use.
   *     See issue #227 for further information.
   * @param {Boolean} [opts.useGirderAuthorizationHeader=false] Whether to use `Authorization` or
   *     `Girder-Authorization` as the header containing the basic auth credentials.
   * @param {Boolean} [opts.setLocalCookie=true] Whether to set the authentication token to a local
   *     cookie (via Javascript) after login to a server.
   */
  constructor({
    apiRoot = '/api/v1',
    token = setCookieFromHash(window.location) || cookies.get('girderToken'),
    axios = axios_.create(),
    authenticateWithCredentials = false,
    useGirderAuthorizationHeader = false,
    setLocalCookie = true,
  } = {}) {
    super({
      data: {
        user: null,
        token,
      },
    });

    Object.assign(this, axios, {
      apiRoot,
      setLocalCookie,
      authenticateWithCredentials,
      useGirderAuthorizationHeader,
    });

    this.interceptors.request.use((config) => ({
      ...config,
      baseURL: this.apiRoot,
      headers: {
        [GirderToken]: this.token,
        ...config.headers,
      },
    }));
  }

  async login(username, password, otp = null) {
    try {
      await this.logout();
    } catch (err) {
      // noop
    }

    let auth;
    const headers = {
      [GirderToken]: null,
    };
    if (this.useGirderAuthorizationHeader) {
      headers[GirderAuthorization] = `Basic ${window.btoa(`${username}:${password}`)}`;
    } else {
      auth = {
        username,
        password,
      };
    }
    if (otp) {
      headers[GirderOtp] = otp;
    }

    const resp = await this.get('user/authentication', {
      headers, auth, withCredentials: this.authenticateWithCredentials,
    });
    this.token = resp.data.authToken.token;
    this.user = resp.data.user;

    if (this.setLocalCookie) {
      setCookieFromAuth(resp.data.authToken);
    }
    this.$emit('login', this.user);
    return resp;
  }

  async logout() {
    if (!this.token) {
      return;
    }
    try {
      await this.delete('user/authentication');
    } catch (err) {
      if (err.response.status !== 401) {
        throw err;
      }
    } finally {
      this.token = null;
      this.user = null;
      cookies.remove('girderToken');
      this.$emit('logout');
    }
  }

  async fetchUser() {
    const resp = await this.get('user/me');
    this.user = resp.data;
    if (this.user === null) {
      this.token = null;
    }
    return this.user;
  }

  async register(login, email, firstName, lastName, password, admin = false) {
    const resp = await this.post('user', stringify({
      login, email, firstName, lastName, password, admin,
    }));
    if (!resp.data.authToken) {
      return resp;
    }
    this.token = resp.data.authToken.token;
    this.user = resp.data;
    if (this.setLocalCookie) {
      setCookieFromAuth(resp.data.authToken);
    }
    this.$emit('register', this.user);
    this.$emit('login', this.user);
    return resp;
  }
}
