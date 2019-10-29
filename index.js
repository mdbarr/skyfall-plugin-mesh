'use strict';

const tls = require('tls');
const async = require('async');
const crypto = require('crypto');
const selfsigned = require('selfsigned');
const CircularSeen = require('./circularSeen');

const IV_LENGTH = 16;

function Mesh(skyfall, options) {
  this.id = skyfall.utils.id();

  this.version = require('./package').version;

  this.algorithm = 'aes-256-cbc';
  this.keepAlive = true;
  this.challengeSize = 32;

  this.node = 'peer';
  this.pattern = '*';
  this.condition = {};

  this.stats = {
    received: 0,
    transmitted: 0
  };

  this.heartbeatInterval = 60000;

  const connections = new Map();

  let configured = false;
  const configuration = { id: this.id };

  const addConnection = ({
    socket, type, secret, callback
  }) => {
    socket.setKeepAlive(this.keepAlive);

    const connection = {
      id: skyfall.utils.id(),
      address: socket.address(),
      type,
      secret,
      connected: true,
      authenticated: false,
      state: 'authenticating',
      challenge: this.challenge(),
      callbacks: {
        connected: this.once(callback),
        closed: []
      },
      seen: new CircularSeen()
    };

    skyfall.utils.hidden(connection, 'socket', socket);

    skyfall.utils.hidden(connection, 'send', (data) => {
      if (connection.connected) {
        if (Buffer.isBuffer(data) || typeof data === 'string') {
          connection.socket.write(data);
        } else if (data && typeof data === 'object') {
          try {
            data = JSON.stringify(data);
            connection.socket.write(data);
          } catch (error) {
            console.log('Error in mesh send', error, data);
          }
        } else {
          console.log('Unknown data type in send', data);
        }
      }
    });

    skyfall.utils.hidden(connection, 'close', (done) => {
      done = this.callback(done);

      if (!connection.connected) {
        return done();
      }
      connection.callbacks.closed.push(done);
      return socket.end();
    });

    socket.on('close', (hadError) => {
      connection.connected = false;

      if (connections.has(connection.id)) {
        connections.delete(connection.id);
      }

      if (!connection.authenticated) {
        connection.state = 'failed';

        const error = new Error('authentication failed');

        skyfall.events.emit({
          type: 'mesh:peer:error',
          data: error,
          source: this.id
        });

        return connection.callbacks.connected(error);
      } else if (hadError) {
        connection.state = 'error';
        const error = connection.error || new Error('protocol error');

        skyfall.events.emit({
          type: 'mesh:peer:error',
          data: error,
          source: this.id
        });

        for (const done of connection.callbacks.closed) {
          done(error);
        }
        return true;
      }

      connection.state = 'closed';

      skyfall.events.emit({
        type: 'mesh:peer:disconnected',
        data: connection,
        source: this.id
      });

      for (const done of connection.callbacks.closed) {
        done(null);
      }
      return true;
    });

    socket.on('end', () => {
      connection.stating = 'closing';
    });

    socket.on('error', (error) => {
      connection.state = 'error';
      connection.error = error;
    });

    socket.on('data', (data) => {
      let message;
      try {
        message = JSON.parse(data);
      } catch (error) {
        skyfall.events.emit({
          type: 'mesh:server:error',
          data: error,
          source: this.id
        });
      }

      if (!message) {
        if (!connection.authenticated) {
          return connection.close();
        }
        return false;
      }

      if (connection.authenticated) {
        if (this.role !== 'producer' && message.object === 'event' &&
            !connection.seen.has(message.id) && message.origin !== skyfall.events.id) {
          connection.seen.add(message.id);

          this.stats.received++;

          skyfall.events.emit(message);
        }
        return true;
      } else if (type === 'server') {
        if (message.object === 'counter') {
          if (message.answer === connection.challenge) {
            return connection.send({
              object: 'response',
              answer: this.decrypt(message.counter, connection.secret)
            });
          }
        } else if (message.object === 'authenticated') {
          connection.peer = this.peer(message);

          connection.authenticated = true;
          connection.state = 'authenticated';

          this.listener(skyfall, connection);

          connection.send({
            object: 'authenticated',
            ...this.describe(skyfall)
          });

          skyfall.events.emit({
            type: 'mesh:peer:authenticated',
            data: connection.peer,
            source: this.id
          });

          return connection.callbacks.connected(null, connection);
        }
      } else if (type === 'client') {
        if (message.object === 'challenge') {
          return connection.send({
            object: 'counter',
            answer: this.decrypt(message.challenge, connection.secret),
            counter: this.encrypt(connection.challenge, connection.secret)
          });
        } else if (message.object === 'response') {
          if (message.answer === connection.challenge) {
            return connection.send({
              object: 'authenticated',
              ...this.describe(skyfall)
            });
          }
        } else if (message.object === 'authenticated') {
          connection.peer = this.peer(message);

          connection.authenticated = true;
          connection.state = 'authenticated';

          this.listener(skyfall, connection);

          skyfall.events.emit({
            type: 'mesh:peer:authenticated',
            data: connection.peer,
            source: this.id
          });

          return connection.callbacks.connected(null, connection);
        }
      }

      return connection.close();
    });

    connections.set(connection.id, connection);

    skyfall.events.emit({
      type: 'mesh:peer:connected',
      data: connection,
      source: this.id
    });

    if (connection.type === 'server') {
      connection.state = 'challenge';
      connection.send({
        object: 'challenge',
        challenge: this.encrypt(connection.challenge, connection.secret)
      });
    }

    return connection;
  };

  this.connect = (config, callback) => {
    callback = this.callback(callback);

    if (!configured) {
      const error = new Error('mesh networking not configured');

      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: this.id
      });

      return callback(error);
    }

    const socket = tls.connect({
      host: config.remoteHost || 'localhost',
      port: config.remotePort || configuration.port,
      rejectUnauthorized: config.rejectUnauthorized !== undefined ?
        config.rejectUnauthorized : false
    }, () => {
      return addConnection({
        socket,
        type: 'client',
        secret: config.secret || configuration.secret,
        callback
      });
    });

    skyfall.events.emit({
      type: 'mesh:peer:connecting',
      data: config,
      source: this.id
    });

    return true;
  };

  this.configure = (config) => {
    this.algorithm = config.algorithm || this.algorithm;
    this.keepAlive = config.keepAlive !== undefined ? config.keepAlive : this.keepAlive;
    this.challengeSize = config.challengeSize || this.challengeSize;
    this.heartbeatInterval = Number(config.heartbeatInterval) || this.heartbeatInterval;

    if (config.peer) {
      this.node = 'peer';
    } else if (config.consumer) {
      this.node = 'consumer';
    } else if (config.producer) {
      this.node = 'producer';
    }

    if (config.pattern) {
      this.pattern = config.pattern;
    }

    if (config.condition || config.filter) {
      this.condition = config.condition || config.filter;
    }

    const host = config.host || '0.0.0.0';
    const port = Number(config.port) || 7527;
    const secret = config.secret || skyfall.utils.id();

    if (!config.key || !(config.cert || config.certificate)) {
      const attributes = [ {
        name: 'commonName',
        value: config.commonName || 'hyperingenuity.com'
      } ];
      const pems = selfsigned.generate(attributes, { days: 365 });

      config.key = pems.private;
      config.cert = pems.cert;
    }

    const key = config.key;
    const cert = config.cert || config.certificate;

    Object.assign(configuration, {
      host,
      port,
      secret,
      key,
      cert,
      get connections() {
        return connections.size;
      }
    });

    configured = true;

    if (this.interval) {
      clearInterval(this.interval);
    }

    this.heartbeat = () => {
      skyfall.events.emit({
        type: 'mesh:peer:heartbeat',
        data: {
          identity: skyfall.config.identity,
          bus: skyfall.events.id,
          node: this.node,
          stats: this.stats,
          connections: connections.size
        }
      });
    };

    this.interval = setInterval(this.heartbeat, this.heartbeatInterval);

    this.heartbeat();

    return configuration;
  };

  this.start = (callback) => {
    callback = this.callback(callback);

    if (!configured) {
      const error = new Error('mesh networking not configured');

      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: this.id
      });

      return callback(error);
    } else if (this.node !== 'peer') {
      const error = new Error('mesh server can only be started for "peer" nodes');

      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: this.id
      });

      return callback(error);
    }

    skyfall.events.emit({
      type: 'mesh:server:starting',
      data: configuration,
      source: this.id
    });

    this.server = tls.createServer(configuration, (socket) => {
      addConnection({
        socket,
        type: 'server',
        secret: configuration.secret
      });
    });

    this.server.listen(configuration.port, configuration.host, (error) => {
      if (error) {
        skyfall.events.emit({
          type: 'mesh:server:error',
          data: error,
          source: this.id
        });

        return callback(error);
      }

      skyfall.events.emit({
        type: 'mesh:server:started',
        data: configuration,
        source: this.id
      });

      return callback(null);
    });

    return true;
  };

  this.stop = (callback) => {
    callback = this.callback(callback);
    const tasks = [];

    for (const [ , connection ] of connections) {
      tasks.push(connection.close);
    }

    return async.series(tasks, () => {
      if (this.server) {
        return this.server.close(() => {
          return callback();
        });
      }
      return callback();
    });
  };

  if (Object.keys(options).length) {
    this.configure(options);
  }
}

Mesh.prototype.challenge = function() {
  return crypto.randomBytes(this.challengeSize).toString('hex');
};

Mesh.prototype.encrypt = function(text, secret) {
  let encrypted = null;
  try {
    secret = secret.replace(/-/g, '').substring(0, 32);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(this.algorithm, secret, iv);
    encrypted = cipher.update(text);
    encrypted = Buffer.concat([ encrypted, cipher.final() ]);
    encrypted = `${ iv.toString('hex') }:${ encrypted.toString('hex') }`;
  } catch (error) {
    console.log('Mesh encrypt error', error);
  }

  return encrypted;
};

Mesh.prototype.decrypt = function(text, secret) {
  let decrypted = null;
  try {
    secret = secret.replace(/-/g, '').substring(0, 32);
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(this.algorithm, secret, iv);
    decrypted = decipher.update(encryptedText);

    decrypted = Buffer.concat([ decrypted, decipher.final() ]).toString();
  } catch (error) {
    console.log('Mesh decrypt error', error);
  }

  return decrypted;
};

Mesh.prototype.callback = function(callback) {
  if (typeof callback !== 'function') {
    return () => { return true; };
  }
  return callback;
};

Mesh.prototype.once = function(func) {
  if (typeof func !== 'function') {
    return () => {};
  }

  let invoked = false;

  return (...args) => {
    if (!invoked) {
      invoked = true;
      return func(...args);
    }
    return false;
  };
};

Mesh.prototype.describe = function(skyfall) {
  return {
    skyfall: skyfall.version,
    mesh: this.version,
    identity: skyfall.config.identity,
    bus: skyfall.events.id,
    node: this.node,
    pattern: this.pattern,
    condition: this.condition
  };
};

Mesh.prototype.peer = function(message) {
  return {
    skyfall: message.skyfall,
    mesh: message.mesh,
    identity: message.identity,
    bus: message.bus,
    node: message.node,
    pattern: message.pattern,
    condition: message.condition
  };
};

Mesh.prototype.listener = function(skyfall, connection) {
  if (this.node !== 'consumer') {
    if (connection.peer.node === 'peer') {
      skyfall.events.all((event) => {
        if (!connection.seen.has(event.id)) {
          connection.seen.add(event.id);

          if (connection.connected) {
            connection.send(event);
            this.stats.transmitted++;
          }
        }
      });
    } else if (connection.peer.node === 'consumer') {
      skyfall.events.on(connection.peer.pattern, connection.peer.condition, (event) => {
        if (!connection.seen.has(event.id)) {
          connection.seen.add(event.id);

          if (connection.connected) {
            connection.send(event);
            this.stats.transmitted++;
          }
        }
      });
    }
  }
};

module.exports = {
  name: 'mesh',
  install: (skyfall, options) => {
    skyfall.mesh = new Mesh(skyfall, options);
  }
};
