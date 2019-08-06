'use strict';

const fs = require('fs');
const tls = require('tls');
const async = require('async');
const crypto = require('crypto');

function CircularSeen(capacity = 100) {
  const seen = new Array(capacity);
  const set = new WeakSet();

  let start = 0;
  let size = 0;

  this.size = () => { return size; };

  this.add = (item) => {
    if (start > 0) {
      start--;
    } else {
      start = capacity - 1;
    }

    if (seen[start]) {
      set.delete(seen[start]);
    }

    seen[start] = item;
    set.add(item);

    if (size < capacity) {
      size++;
    }
  };

  this.has = (item) => {
    return set.has(item);
  };
}

function Mesh(skyfall, options) {
  const id = skyfall.utils.id();

  this.version = require('./package').version;

  this.algorithm = 'aes-256-cbc';
  this.keepAlive = true;
  this.challengeSize = 32;

  this.node = 'peer';
  this.pattern = '*';
  this.condition = {};

  const connections = new Map();
  const seen = new CircularSeen();

  let configured = false;
  const configuration = { id };

  const stats = {
    received: 0,
    transmitted: 0
  };

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
      }
    };

    skyfall.utils.hidden(connection, 'socket', socket);

    skyfall.utils.hidden(connection, 'send', (data) => {
      if (connection.connected) {
        if (Buffer.isBuffer(data) || typeof data === 'string') {
          connection.socket.write(data);
        } else {
          data = JSON.stringify(data);
          connection.socket.write(data);
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
          source: id
        });

        return connection.callbacks.connected(error);
      } else if (hadError) {
        connection.state = 'error';
        const error = connection.error || new Error('protocol error');

        skyfall.events.emit({
          type: 'mesh:peer:error',
          data: error,
          source: id
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
        source: id
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
          source: id
        });
      }

      if (!message) {
        return connection.close();
      }

      if (connection.authenticated) {
        if (message.object === 'event' &&
            !seen.has(message) && message.origin !== skyfall.events.id) {
          seen.add(message);
          stats.received++;
          skyfall.events.emit(message);

          for (const [ , client ] of connections) {
            if (client.id !== connection.id && client.connected && client.authenticated) {
              client.send(message);
            }
          }
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

          connection.send({
            object: 'authenticated',
            ...this.describe(skyfall)
          });

          skyfall.events.emit({
            type: 'mesh:peer:authenticated',
            data: connection.peer,
            source: id
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

          skyfall.events.emit({
            type: 'mesh:peer:authenticated',
            data: connection.peer,
            source: id
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
      source: id
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

  skyfall.events.all((event) => {
    if (event.source !== id && !seen.has(event)) {
      seen.add(event);

      for (const [ , connection ] of connections) {
        if (connection.state === 'authenticated') {
          connection.send(event);
          stats.transmitted++;
        }
      }
    }
  });

  this.connect = (config, callback) => {
    callback = this.callback(callback);

    if (!configured) {
      const error = new Error('mesh networking not configured');

      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: id
      });

      return callback(error);
    }

    const socket = tls.connect({
      host: config.host || 'localhost',
      port: config.port || configuration.port,
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
      source: id
    });

    return true;
  };

  this.configure = (config) => {
    this.algorithm = config.algorithm || this.algorithm;
    this.keepAlive = config.keepAlive !== undefined ? config.keepAlive : this.keepAlive;
    this.challengeSize = config.challengeSize || this.challengeSize;

    if (config.peer) {
      this.node = 'peer';
    } else if (config.consumer) {
      this.node = 'consumer';
    } else if (config.producer) {
      this.node = 'producer';
    }

    const host = config.host || '0.0.0.0';
    const port = Number(config.port) || 7527;
    const secret = config.secret || skyfall.utils.id();

    const key = config.key ? fs.readFileSync(config.key).toString() : null;
    const cert = config.certificate || config.cert ?
      fs.readFileSync(config.certificate || config.cert).toString() : null;

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

    return configuration;
  };

  this.start = (callback) => {
    callback = this.callback(callback);

    if (!configured) {
      const error = new Error('mesh networking not configured');

      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: id
      });

      return callback(error);
    }

    skyfall.events.emit({
      type: 'mesh:server:starting',
      data: configuration,
      source: id
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
          source: id
        });

        return callback(error);
      }

      skyfall.events.emit({
        type: 'mesh:server:started',
        data: configuration,
        source: id
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
  const cipher = crypto.createCipher(this.algorithm, secret);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return encrypted;
};

Mesh.prototype.decrypt = function(text, secret) {
  const decipher = crypto.createDecipher(this.algorithm, secret);

  let deciphered;
  try {
    deciphered = decipher.update(text, 'hex', 'utf8');
    deciphered += decipher.final('utf8');
  } catch (error) {
    deciphered = false;
  }

  return deciphered;
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

module.exports = {
  name: 'mesh',
  install: (skyfall, options) => {
    skyfall.mesh = new Mesh(skyfall, options);
  }
};
