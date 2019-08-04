'use strict';

const fs = require('fs');
const tls = require('tls');

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

  const addConnection = (socket, direction) => {
    const connection = {
      id: skyfall.utils.id(),
      address: socket.address(),
      direction,
      authenticated: false,
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
              console.log('write error');
            }
          });
        }
      }
    });

    skyfall.utils.hidden(connection, 'auth', () => {
      connection.send({
        object: 'authentication',
        secret: configuration.secret,
        identity: skyfall.config.identity,
        bus: skyfall.events.id
      });
    });

    socket.on('end', () => {
      connection.ready = false;
      if (connections.has(connection.id)) {
        connections.delete(connection.id);
      }
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
      console.log('got data', data.toString());
      try {
        const event = JSON.parse(data);
        console.log('got event');
        console.pp(event);
        if (!seen.has(event) && event.origin !== skyfall.events.id) {
          seen.add(event);
          stats.received++;
          skyfall.events.emit(event);
        }
      } catch (error) {
        skyfall.events.emit({
          type: 'mesh:server:error',
          data: error,
          source: id
        });
      }
    });

    connections.set(connection.id, connection);
    return connection;
  };

  skyfall.events.on('*', (event) => {
    if (!seen.has(event)) {
      seen.add(event);

      for (const [ , connection ] of connections) {
        connection.send(event);
        stats.transmitted++;
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
      const connection = addConnection(socket, 'outgoing');

      connection.auth();

      if (typeof callback === 'function') {
        return callback(null);
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
      console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');

      addConnection(socket, 'incoming');
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
      console.log('ending');
      console.pp(connection);
      connection.socket.end();
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

module.exports = {
  name: 'mesh',
  install: (skyfall, options) => {
    skyfall.mesh = new Mesh(skyfall, options);
  }
};
