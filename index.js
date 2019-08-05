'use strict';

const CIPHER_ALGORITHM = 'aes-256-cbc';

const fs = require('fs');
const tls = require('tls');
const crypto = require('crypto');

function Mesh(skyfall, options) {
  const id = skyfall.utils.id();

  const connections = new Map();
  const seen = new WeakSet();

  let configured = false;
  const configuration = { id };

  const stats = {
    received: 0,
    transmitted: 0
  };

  const addConnection = (socket, direction, secret) => {
    const connection = {
      id: skyfall.utils.id(),
      address: socket.address(),
      direction,
      secret,
      authenticated: false,
      challenge: crypto.randomBytes(32).toString('hex'),
      ready: true
    };

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

    skyfall.utils.hidden(connection, 'auth', () => {
      connection.send({
        object: 'challenge',
        challenge: this.encrypt(connection.challenge, connection.secret)
      });
    });

    skyfall.utils.hidden(connection, 'close', () => {
      connection.ready = false;
      if (connections.has(connection.id)) {
        connections.delete(connection.id);
      }
      socket.end();

      skyfall.events.emit({
        type: 'mesh:client:disconnected',
        data: connection,
        source: id
      });
    });

    socket.on('end', () => {
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

      if (connection.authenticated && message.object === 'event') {
        if (!seen.has(message) && message.origin !== skyfall.events.id) {
          seen.add(message);
          stats.received++;
          skyfall.events.emit(message);
        }

        for (const [ , client ] of connections) {
          if (client.id !== connection.id) {
            client.send(message);
          }
        }
      } else if (message.object === 'challenge') {
        const answer = this.decrypt(message.challenge, connection.secret);
        connection.send({
          object: 'answer',
          answer
        });
      } else if (message.object === 'answer') {
        if (message.answer === connection.challenge) {
          connection.send({
            object: 'authenticated',
            identity: skyfall.config.identity,
            bus: skyfall.events.id
          });
          connection.authenticated = true;
        } else {
          connection.close();
        }
      } else if (message.object === 'authenticated') {
        connection.peer = message;
        skyfall.events.emit({
          type: 'mesh:client:authenticated',
          data: connection,
          source: id
        });
      } else {
        connection.socket.end();
      }
    });

    connections.set(connection.id, connection);

    skyfall.events.emit({
      type: 'mesh:client:connected',
      data: connection,
      source: id
    });

    connection.auth();

    return connection;
  };

  skyfall.events.on('*', (event) => {
    if (event.source !== id && !seen.has(event)) {
      seen.add(event);

      for (const [ , connection ] of connections) {
        if (connection.authenticated) {
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
      const connection = addConnection(socket, 'outgoing', config.secret || configuration.secret);

      if (typeof callback === 'function') {
        return callback(null, connection);
      }

      return true;
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
      addConnection(socket, 'incoming', configuration.secret);
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
  let deciphered = decipher.update(text, 'hex', 'utf8');
  deciphered += decipher.final('utf8');
  return deciphered;
};

module.exports = {
  name: 'mesh',
  install: (skyfall, options) => {
    skyfall.mesh = new Mesh(skyfall, options);
  }
};
