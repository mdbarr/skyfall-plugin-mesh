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

  const addConnection = (socket) => {
    const connection = {
      id: skyfall.utils.id(),
      socket,
      address: socket.address(),
      authenticated: false
    };

    socket.on('data', (data) => {
      try {
        const event = JSON.parse(data);
        if (!seen.has(event.id) && event.origin !== skyfall.events.id) {
          seen.add(event.id);
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
    if (!seen.has(event.id)) {
      seen.add(event.id);

      const message = JSON.stringify(event);

      for (const [ , connection ] of connections) {
        connection.write(message);
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
      socket.write({ authentication: configuration.secret });

      socket.on('end', () => {
        console.log('server ends connection');
      });

      socket.on('error', (error) => {
        skyfall.events.emit({
          type: 'mesh:server:error',
          data: error,
          source: id
        });
      });

      const connection = addConnection(socket);

      connections.set(id, connection);

      if (typeof callback === 'function') {
        return callback();
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

    const key = config.key ? fs.readFileSync(config.key) : null;
    const cert = config.certificate || config.cert ?
      fs.readFileSync(config.certificate || config.cert) : null;

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
      data: this.configuration,
      source: id
    });

    this.server = tls.createServer(this.configuration, (socket) => {
      console.log('server connected',
        socket.authorized ? 'authorized' : 'unauthorized');
      socket.write('welcome!\n');
      socket.setEncoding('utf8');
      socket.pipe(socket);
    });

    this.server.listen(this.configuration.port, this.configuration.host, (error) => {
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
        data: this.configuration,
        source: id
      });

      if (typeof callback === 'function') {
        return callback();
      }
      return true;
    });

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
