'use strict';

function Mesh(skyfall, options) {
  const id = skyfall.utils.id();

  const incoming = new Map();
  const outgoing = new Map();
  const seen = new WeakSet();

  const stats = {
    received: 0,
    transmitted: 0
  };

  this.configure = (config) => {
    const host = config.host || '0.0.0.0';
    const port = Number(config.port) || 7527;
    const secret = config.secret || skyfall.utils.id();

    this.configuration = {
      id,
      host,
      port,
      secret,
      get incoming() {
        return incoming.size;
      },
      get outgoing() {
        return outgoing.size;
      }
    };

    return this.configuration;
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
