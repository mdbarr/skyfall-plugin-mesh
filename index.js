'use strict';

const CIPHER_ALGORITHM = 'aes-256-cbc';

const fs = require('fs');
const tls = require('tls');
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
    const connection = {
      id: skyfall.utils.id(),
      address: socket.address(),
      type,
      secret,
      state: 'connected',
      challenge: crypto.randomBytes(32).toString('hex'),
      ready: true
    };

    callback = this.once(callback);

    skyfall.utils.hidden(connection, 'socket', socket);

    skyfall.utils.hidden(connection, 'send', (data) => {
      if (connection.ready) {
        if (Buffer.isBuffer(data) || typeof data === 'string') {
          connection.socket.write(data);
        } else {
          data = JSON.stringify(data);
          connection.socket.write(data, (error) => {
            if (error) {
              connection.close();
            }
          });
        }
      }
    });

    skyfall.utils.hidden(connection, 'close', this.once(() => {
      connection.ready = false;
      if (connections.has(connection.id)) {
        connections.delete(connection.id);
      }

      if (!socket.ended) {
        socket.end();
      }

      if (connection.state === 'connected') {
        const error = new Error('protocol error');

        skyfall.events.emit({
          type: 'mesh:peer:error',
          data: error,
          source: id
        });

        return callback(error);
      }

      skyfall.events.emit({
        type: 'mesh:peer:disconnected',
        data: connection,
        source: id
      });

      return true;
    }));

    socket.on('end', () => {
      socket.ended = true;
      connection.close();
    });

    socket.on('error', (error) => {
      connection.ready = false;
      if (connections.has(connection.id)) {
        connections.delete(connection.id);
      }
      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: id
      });
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

      if (connection.state === 'authenticated') {
        if (message.object === 'event' &&
            !seen.has(message) && message.origin !== skyfall.events.id) {
          seen.add(message);
          stats.received++;
          skyfall.events.emit(message);

          for (const [ , client ] of connections) {
            if (client.id !== connection.id && connection.ready) {
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
          connection.peer = {
            identity: message.identity,
            bus: message.bus
          };
          connection.state = 'authenticated';

          connection.send({
            object: 'authenticated',
            identity: skyfall.config.identity,
            bus: skyfall.events.id
          });

          skyfall.events.emit({
            type: 'mesh:peer:authenticated',
            data: connection.client,
            source: id
          });

          return callback(null, connection);
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
              identity: skyfall.config.identity,
              bus: skyfall.events.id
            });
          }
        } else if (message.object === 'authenticated') {
          connection.peer = {
            identity: message.identity,
            bus: message.bus
          };
          connection.state = 'authenticated';

          skyfall.events.emit({
            type: 'mesh:peer:authenticated',
            data: connection.server,
            source: id
          });

          return callback(null, connection);
        }
      }

      return connection.close();
    });

    connections.set(connection.id, connection);

    skyfall.events.emit({
      type: 'mesh:client:connected',
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

  skyfall.events.on('*', (event) => {
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
    if (!configured) {
      const error = new Error('mesh networking not configured');

      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: id
      });

      if (typeof callback === 'function') {
        return callback(error);
      }
      return false;
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
      type: 'mesh:client:connecting',
      data: config,
      source: id
    });

    return true;
  };

  this.configure = (config) => {
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
    if (!configured) {
      const error = new Error('mesh networking not configured');

      skyfall.events.emit({
        type: 'mesh:server:error',
        data: error,
        source: id
      });

      if (typeof callback === 'function') {
        return callback(error);
      }
      return false;
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

        if (typeof callback === 'function') {
          return callback(error);
        }

        return error;
      }
      skyfall.events.emit({
        type: 'mesh:server:started',
        data: configuration,
        source: id
      });

      if (typeof callback === 'function') {
        return callback(null);
      }
      return true;
    });

    return true;
  };

  this.stop = (callback) => {
    for (const [ , connection ] of connections) {
      connection.close();
    }

    if (this.server) {
      return this.server.close(callback);
    } else if (typeof callback === 'function') {
      return callback(null);
    }
    return true;
  };

  if (Object.keys(options).length) {
    this.configure(options);
  }
}

Mesh.prototype.encrypt = function(text, secret) {
  const cipher = crypto.createCipher(CIPHER_ALGORITHM, secret);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return encrypted;
};

Mesh.prototype.decrypt = function(text, secret) {
  const decipher = crypto.createDecipher(CIPHER_ALGORITHM, secret);

  let deciphered;
  try {
    deciphered = decipher.update(text, 'hex', 'utf8');
    deciphered += decipher.final('utf8');
  } catch (error) {
    deciphered = false;
  }

  return deciphered;
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

module.exports = {
  name: 'mesh',
  install: (skyfall, options) => {
    skyfall.mesh = new Mesh(skyfall, options);
  }
};
