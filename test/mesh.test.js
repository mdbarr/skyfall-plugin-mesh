'use strict';

require('barrkeep/pp');
const path = require('path');
const Skyfall = require('@mdbarr/skyfall');
const skyfall = new Skyfall({ api: { port: 0 } });

describe('Skyfall Mesh Networking Test', () => {
  it('should register the mesh plugin', () => {
    skyfall.use(require('../index'));
  });

  it('should configure the mesh plugin', () => {
    const configuration = skyfall.mesh.configure({
      host: '0.0.0.0',
      port: 7537,
      secret: 'bc6383f0-b6e7-11e9-9f74-0348351cafd3',
      key: path.join(__dirname, 'mesh.test.key.pem'),
      cert: path.join(__dirname, 'mesh.test.cert.pem')
    });

    console.pp(configuration);
  });

  it('should start the mesh server', (done) => {
    skyfall.mesh.start((error) => {
      expect(error).toBeNull();
      done();
    });
  });

  it('should connect to the local mesh server', (done) => {
    skyfall.mesh.connect({
      host: 'localhost',
      port: 7537
    }, done);
  });

  it('should receive authenticated event', (done) => {
    skyfall.events.once('mesh:client:authenticated', (event) => {
      console.pp(event);
      done();
    });
  });

  it('should stop the mesh server', (done) => {
    skyfall.mesh.stop();
    setTimeout(done, 2500);
  });
});
