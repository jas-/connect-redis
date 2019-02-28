/*!
 * Connect - Redis
 * Copyright(c) 2012 TJ Holowaychuk <tj@vision-media.ca>
 * MIT Licensed
 */

var debug = require('debug')('connect:redis');
var crypto = require('crypto');
var util = require('util');
var noop = function(){};

/**
 * One day in seconds.
 */

var oneDay = 86400;

function getTTL(store, sess, sid) {
  if (typeof store.ttl === 'number' || typeof store.ttl === 'string') return store.ttl;
  if (typeof store.ttl === 'function') return store.ttl(store, sess, sid);
  if (store.ttl) throw new TypeError('`store.ttl` must be a number or function.');

  var maxAge = sess.cookie.maxAge;
  return (typeof maxAge === 'number'
    ? Math.floor(maxAge / 1000)
    : oneDay);
}

/**
 * Return the `RedisStore` extending `express`'s session Store.
 *
 * @param {object} express session
 * @return {Function}
 * @api public
 */

module.exports = function (session) {

  /**
   * Express's session Store.
   */

  var Store = session.Store;

  /**
   * Initialize RedisStore with the given `options`.
   *
   * @param {Object} options
   * @api public
   */

  function RedisStore (options) {
    if (!(this instanceof RedisStore)) {
      throw new TypeError('Cannot call RedisStore constructor as a function');
    }

    var self = this;

    options = options || {};
    Store.call(this, options);
    this.prefix = options.prefix == null
      ? 'sess:'
      : options.prefix;

    delete options.prefix;

    this.scanCount = Number(options.scanCount) || 100;
    delete options.scanCount;

    this.serializer = options.serializer || JSON;

    this.secret = derive_key(options.secret) || false;
    this.algorithm = options.algorithm || 'aes-256-gcm';
    this.hashing = options.hashing || 'sha512';
    this.encodeas = options.encodeas || 'hex';

    if (options.url) {
      options.socket = options.url;
    }

    // convert to redis connect params
    if (options.client) {
      this.client = options.client;
    } else {
      var redis = require('redis');

      if (options.socket) {
        this.client = redis.createClient(options.socket, options);
      }
      else {
        this.client = redis.createClient(options);
      }
    }

    // logErrors
    if(options.logErrors){
      // if options.logErrors is function, allow it to override. else provide default logger. useful for large scale deployment
      // which may need to write to a distributed log
      if(typeof options.logErrors != 'function'){
        options.logErrors = function (err) {
          console.error('Warning: connect-redis reported a client error: ' + err);
        };
      }
      this.client.on('error', options.logErrors);
    }

    if (options.pass) {
      this.client.auth(options.pass, function (err) {
        if (err) {
          throw err;
        }
      });
    }

    this.ttl = options.ttl;
    this.disableTTL = options.disableTTL;

    if (options.unref) this.client.unref();

    if ('db' in options) {
      if (typeof options.db !== 'number') {
        console.error('Warning: connect-redis expects a number for the "db" option');
      }

      self.client.select(options.db);
      self.client.on('connect', function () {
        self.client.select(options.db);
      });
    }

    self.client.on('error', function (er) {
      debug('Redis returned err', er);
      self.emit('disconnect', er);
    });

    self.client.on('connect', function () {
      self.emit('connect');
    });
  }

  /**
   * Wrapper to create cipher text, digest & encoded payload
   */

  function encryptData(plaintext) {
    var iv = crypto.randomBytes(16).toString(this.encodeas);

    var aad = digest(this.secret, this.serializer.stringify(plaintext),
                     this.hashing, this.encodeas);

    var ct = encrypt(this.secret, this.serializer.stringify(plaintext),
                     this.algorithm, this.encodeas, iv, aad);

    var hmac = digest(this.secret, ct.ct, this.hashing, this.encodeas);

    var obj = {
      hmac: hmac,
      ct: ct.ct,
      at: ct.at,
      aad: aad,
      iv: iv
    };

    debug('encryptData %s', this.serializer.stringify(obj));

    return this.serializer.stringify(obj);
  }

  /**
   * Wrapper to extract digest, verify digest & decrypt cipher text
   */

  function decryptData(ciphertext) {
    debug('decryptData %s', ciphertext);

    if (ciphertext)
      ciphertext = this.serializer.parse(ciphertext);

    var hmac = digest(this.secret, ciphertext.ct, this.hashing, this.encodeas);

    debug('HMAC %s %s', ciphertext.hmac, hmac);

    if (hmac != ciphertext.hmac) {
      throw 'Encrypted session was tampered with!';
    }

    var pt = decrypt(this.secret, ciphertext.ct, this.algorithm,
                     this.encodeas, ciphertext.iv, Buffer.from(ciphertext.at),
                     ciphertext.aad);

    debug('PT %s %s', pt, typeof pt);

    return this.serializer.parse(pt);
  }

  /**
   * Generates HMAC as digest of cipher text
   */

  function digest(key, obj, hashing, encodeas) {
    var hmac = crypto.createHmac(hashing, key);
    hmac.setEncoding(encodeas);
    hmac.write(obj);
    hmac.end();
    return hmac.read().toString(encodeas);
  }

  /**
   * Creates cipher text from plain text
   */

  function encrypt(key, pt, algo, encodeas, iv, aad) {
    var cipher = crypto.createCipheriv(algo, key, iv, {
      authTagLength: 16
    }), ct, at;

    try {
      cipher.setAAD(Buffer.from(aad), {
        plaintextLength: Buffer.byteLength(pt)
      });
    } catch(e) {
      // Discard as the algo may not support AAD
    }

    ct = cipher.update(pt, 'utf8', encodeas);
    ct += cipher.final(encodeas);

    try {
      at = cipher.getAuthTag();
    } catch(e) {
      // Discard as the algo may not support auth tags
    }

    return (at) ? {'ct': ct, 'at': at} : {'ct': ct};
  }

  /**
   * Creates plain text from cipher text
   */

  function decrypt(key, ct, algo, encodeas, iv, at, aad) {
    var cipher = crypto.createDecipheriv(algo, key, iv)
      , pt;

    try {
      if (at)
        cipher.setAuthTag(Buffer.from(at));
    } catch(e) {
      // Discard as the algo may not support Auth tags
    }

    try {
      if (aad)
        cipher.setAAD(Buffer.from(aad), {plaintextLength: Buffer.byteLength(ct)});
    } catch(e) {
      // Discard as the algo may not support AAD
    }

    pt = cipher.update(ct, encodeas, 'utf8');
    pt += cipher.final('utf8');

    return pt;
  }

  /**
   * Derive key from supplied pass phrase
   */
   
  function derive_key(secret) {
    var key, hash, salt;

    if (!secret)
      return false;

    hash = crypto.createHash('sha512');
    hash.update(secret);
    salt = hash.digest('hex').substr(0, 16);

    key = crypto.pbkdf2Sync(secret, salt, 25000, 64, 'sha512');

    return key.toString('hex').substr(0, 32);
  }

  /**
   * Inherit from `Store`.
   */

  util.inherits(RedisStore, Store);

  /**
   * Attempt to fetch session by the given `sid`.
   *
   * @param {String} sid
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.get = function (sid, fn) {
    var store = this;
    var psid = store.prefix + sid;
    if (!fn) fn = noop;
    debug('GET "%s"', sid);

    store.client.get(psid, function (er, data) {
      if (er) return fn(er);
      if (!data) return fn();

      var result;
      data = data.toString();
      debug('GOT %s', data);

      try {
        if (store.secret) {
          result = store.serializer.parse(decryptData.call(store, data));
        } else {
          result = store.serializer.parse(data);
        }
      }
      catch (er) {
        return fn(er);
      }

      debug('GOT %s', result);

      return fn(null, result);
    });
  };

  /**
   * Commit the given `sess` object associated with the given `sid`.
   *
   * @param {String} sid
   * @param {Session} sess
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.set = function (sid, sess, fn) {
    var store = this;
    var args = [store.prefix + sid];
    if (!fn) fn = noop;

    try {
      var jsess = store.serializer.stringify(sess);
    } catch (er) {
      return fn(er);
    }

    if (this.secret)
      jsess = encryptData.call(this, jsess);

    args.push(jsess);

    if (!store.disableTTL) {
      var ttl = getTTL(store, sess, sid);
      args.push('EX', ttl);
      debug('SET "%s" %s ttl:%s', sid, jsess, ttl);
    } else {
      debug('SET "%s" %s', sid, jsess);
    }

    store.client.set(args, function (er) {
      if (er) return fn(er);
      debug('SET complete');
      fn.apply(null, arguments);
    });
  };

  /**
   * Destroy the session associated with the given `sid`.
   *
   * @param {String} sid
   * @api public
   */

  RedisStore.prototype.destroy = function (sid, fn) {
    debug('DEL "%s"', sid);
    if (Array.isArray(sid)) {
      var multi = this.client.multi();
      var prefix = this.prefix;
      sid.forEach(function (s) {
        multi.del(prefix + s);
      });
      multi.exec(fn);
    } else {
      sid = this.prefix + sid;
      this.client.del(sid, fn);
    }
  };

  /**
   * Refresh the time-to-live for the session with the given `sid`.
   *
   * @param {String} sid
   * @param {Session} sess
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.touch = function (sid, sess, fn) {
    var store = this;
    var psid = store.prefix + sid;
    if (!fn) fn = noop;
    if (store.disableTTL) return fn();

    var ttl = getTTL(store, sess);

    debug('EXPIRE "%s" ttl:%s', sid, ttl);
    store.client.expire(psid, ttl, function (er) {
      if (er) return fn(er);
      debug('EXPIRE complete');
      fn.apply(this, arguments);
    });
  };

  /**
   * Fetch all sessions' Redis keys using non-blocking SCAN command
   *
   * @param {Function} fn
   * @api private
   */

  function allKeys (store, cb) {
    var keysObj = {}; // Use an object to dedupe as scan can return duplicates
    var pattern = store.prefix + '*';
    var scanCount = store.scanCount;
    debug('SCAN "%s"', pattern);
    (function nextBatch (cursorId) {
      store.client.scan(cursorId, 'match', pattern, 'count', scanCount, function (err, result) {
        if (err) return cb(err);

        var nextCursorId = result[0];
        var keys = result[1];

        debug('SCAN complete (next cursor = "%s")', nextCursorId);

        keys.forEach(function (key) {
          keysObj[key] = 1;
        });

        if (nextCursorId != 0) {
          // next batch
          return nextBatch(nextCursorId);
        }

        // end of cursor
        return cb(null, Object.keys(keysObj));
      });
    })(0);
  }

  /**
   * Fetch all sessions' ids
   *
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.ids = function (fn) {
    var store = this;
    var prefixLength = store.prefix.length;
    if (!fn) fn = noop;

    allKeys(store, function (err, keys) {
      if (err) return fn(err);

      keys = keys.map(function (key) {
        return key.substr(prefixLength);
      });
      return fn(null, keys);
    });
  };

  /**
   * Fetch count of all sessions
   *
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.length = function (fn) {
    var store = this;
    if (!fn) fn = noop;

    allKeys(store, function (err, keys) {
      if (err) return fn(err);

      return fn(null, keys.length);
    });
  };


  /**
   * Fetch all sessions
   *
   * @param {Function} fn
   * @api public
   */

  RedisStore.prototype.all = function (fn) {
    var store = this;
    var prefixLength = store.prefix.length;
    if (!fn) fn = noop;

    allKeys(store, function (err, keys) {
      if (err) return fn(err);

      if (keys.length === 0) return fn(null,[]);

      store.client.mget(keys, function (err, sessions) {
        if (err) return fn(err);

        var result;
        try {
          result = sessions.map(function (data, index) {
            data = data.toString();
            if (store.secret)
              data = decryptData.call(store, data);
            data = store.serializer.parse(data);
            data.id = keys[index].substr(prefixLength);
            return data;
          });
        } catch (e) {
          err = e;
        }

        return fn(err, result);
      });
    });
  };

  return RedisStore;
};