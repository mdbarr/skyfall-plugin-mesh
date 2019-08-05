'use strict';

require('barrkeep/pp');
const path = require('path');
const Skyfall = require('@mdbarr/skyfall');

const first = new Skyfall({ api: { port: 0 } });
const second = new Skyfall({ api: { port: 0 } });
const third = new Skyfall({ api: { port: 0 } });

const config = {
  host: '0.0.0.0',
  port: 7537,
  secret: 'bc6383f0-b6e7-11e9-9f74-0348351cafd3',
  key: path.join(__dirname, 'mesh.test.key.pem'),
  cert: path.join(__dirname, 'mesh.test.cert.pem')
};

describe('Skyfall Mesh Networking Test', () => {
  it('should register the mesh plugin', () => {
    first.use(require('../index'));
    second.use(require('../index'));
    third.use(require('../index'));
  });

  it('should configure the mesh plugin', () => {
    first.mesh.configure(config);
    second.mesh.configure(config);
    third.mesh.configure(config);
  });

  it('should start the mesh server', (done) => {
    first.mesh.start((error) => {
      expect(error).toBeNull();
      done();
    });
  });

  it('should connect the second to the first mesh server', (done) => {
    second.mesh.connect({
      host: 'localhost',
      port: 7537
    }, done);
  });

  it('should receive authenticated event', (done) => {
    first.events.once('mesh:client:authenticated', (event) => {
      console.pp(event);
      done();
    });
  });

  it('should connect the third to the first mesh server', (done) => {
    third.mesh.connect({
      host: 'localhost',
      port: 7537
    }, done);
  });

  it('should receive authenticated event', (done) => {
    first.events.once('mesh:client:authenticated', (event) => {
      console.pp(event);
      done();
    });
  });

  it('should emit and receive an event', (done) => {
    third.events.once('test', (event) => {
      expect(event.origin).toBe(second.events.id);
      console.pp(event);
      done();
    });

    second.events.emit({
      type: 'test',
      data: 'foo'
    });
  });

  it('should stop the mesh servers', (done) => {
    first.mesh.stop();
    second.mesh.stop();
    third.mesh.stop();
    setTimeout(done, 2500);
  });
});
