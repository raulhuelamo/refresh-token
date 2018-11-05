var request = require('request');
var EventEmitter = require('events').EventEmitter;

/**
 * Create a new instance of TokenProvider
 *
 * @param {String} url url to get the access token
 * @param {Object} options
 * @return {TokenProvider}
 *
 * options are:
 *  refresh_token
 *  client_id
 *  client_secret
 *
 *  optionals
 *    access_token
 *    expires_in
 */
function TokenProvider(url, options) {
  EventEmitter.call(this);

  if (!(this instanceof TokenProvider)) {
    //when calling as a function, force new.
    return new TokenProvider(url, options);
  }

  if (!url) {
    throw new Error('missing url parameter');
  }

  ['client_id', 'grant_type'].forEach(function (k) {
    if (!(k in options)) {
      throw new Error('missing ' + k + ' parameter');
    }
  });

  this.url = url;
  this.options = options;

  if (this.options.access_token) {
    this.currentToken = {
      access_token: this.options.access_token,
      expires_in: this.options.expires_in,
      expires_in_date: this.options.expires_in_date,
      refresh_token: this.options.refresh_token
    };
  }

  if (this.currentToken && 'expires_in' in this.currentToken) {
    this.currentToken.expires_in_date = new Date(new Date().getTime() + (this.currentToken.expires_in * 1000));
  }
}

TokenProvider.prototype = Object.create(EventEmitter.prototype);

/**
 * Return a valid access token.
 *
 * If the current access token is expired,
 * fetch a new one.
 *
 * @param  {Function} done
 */
TokenProvider.prototype.getToken = function (done) {
  if (this.currentToken && this.currentToken.expires_in_date > new Date()) {
    return done(null, this.currentToken.access_token, this.currentToken.refresh_token);
  }

  const form = ((options) => {
    console.log('options', options);
    const grantType = options.grant_type;
    if (grantType === 'password') {
      return {
        username: options.username,
        password: options.password,
        client_id: options.client_id,
        client_secret: options.client_secret,
        grant_type: 'password'
      }
    }

    return {
      refresh_token: options.refresh_token,
      client_id: options.client_id,
      client_secret: options.client_secret,
      grant_type: 'refresh_token'
    }
  })(this.options);

  request.post({
    url: this.url,
    form
  }, function (err, response, body) {
    if (err) return done(err);

    if (response.statusCode !== 200) {
      var error;
      if (~response.headers['content-type'].indexOf('application/json')) {
        var errorBody = JSON.parse(body);
        error = new Error(errorBody.error);
      } else {
        error = new Error('error refreshing token');
        error.response_body = body;
      }
      return done(error);
    }

    this.currentToken = JSON.parse(body);

    this.currentToken.expires_in_date =
      new Date((new Date()).getTime() + this.currentToken.expires_in * 1000);

    this.options = Object.assign({}, this.options, { refresh_token: this.currentToken.refresh_token });

    this.emit('new token', this.currentToken);

    return done(null, this.currentToken.access_token, this.options.refresh_token);

  }.bind(this));
};

module.exports = TokenProvider;

module.exports.GoogleTokenProvider =
  TokenProvider.bind(null, 'https://accounts.google.com/o/oauth2/token');
