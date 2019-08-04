'use strict';

const fs = require('fs');
const tls = require('tls');

function Mesh(skyfall, options) {
  const id = skyfall.utils.id();

  const incoming = new Map();
  const outgoing = new Map();
  const seen = new WeakSet();

  let configured = false;
  const configuration = { id };

  const stats = {
    received: 0,
    transmitted: 0
  };

  this.connect = (config) => {
    const socket = tls.connect({
      host: config.host || 'localhost',
      port: config.port || configuration.port,
      rejectUnauthorized: config.rejectUnauthorized !== undefined ?
        config.rejectUnauthorized : false
    }, () => {

    });

    socket.on('data', (data) => {
      console.log(data);
    });

    socket.on('end', () => {
      console.log('server ends connection');
    });

    socket.on('error', (error) => {
      console.log(error);
    });

    const connection = {
      socket,
      address: socket.address(),
      authenticated: false
    };
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
      get incoming() {
        return incoming.size;
      },
      get outgoing() {
        return outgoing.size;
      }
    });

    configured = true;

    return configuration;
  };

  this.start = () => {
    if (!configured) {
      skyfall.events.emit({
        type: 'mesh:server:error',
        data: new Error('not configured'),
        source: id
      });

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
      } else {
        skyfall.events.emit({
          type: 'mesh:server:started',
          data: this.configuration,
          source: id
        });
      }
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
