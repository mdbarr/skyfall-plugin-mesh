'use strict';

require('barrkeep/pp');
const { v4: uuid } = require('uuid');
const crypto = require('crypto');
const Skyfall = require('@hyperingenuity/skyfall');

const first = new Skyfall({ api: { port: 0 } });
const second = new Skyfall({ api: { port: 0 } });
const third = new Skyfall({ api: { port: 0 } });

const config = {
  host: '0.0.0.0',
  port: 7537,
  secret: uuid(),
};

describe('Skyfall Mesh Networking Test', () => {
  it('should register the mesh plugin', () => {
    first.use(require('./index'));
    second.use(require('./index'));
    third.use(require('./index'));
  });

  it('should configure the mesh plugin', () => {
    first.mesh.configure(config);

    second.mesh.configure({
      ...config,
      producer: true,
    });

    third.mesh.configure({
      ...config,
      consumer: true,
    });
  });

  it('should start the mesh server', (done) => {
    first.mesh.start((error) => {
      expect(error).toBeNull();
      done();
    });
  });

  it('should connect the second to the first mesh server', (done) => {
    second.mesh.connect({
      remoteHost: 'localhost',
      remotePort: 7537,
    }, done);
  });

  it('should attempt and fail to connect with a bad secret', (done) => {
    third.mesh.connect({
      remoteHost: 'localhost',
      remotePort: 7537,
      secret: 'foooooo',
    }, (error) => {
      expect(error).not.toBeNull();
      done();
    });
  });

  it('should connect the third to the first mesh server', (done) => {
    third.mesh.connect({
      remoteHost: 'localhost',
      remotePort: 7537,
    }, done);
  });

  it('should emit and receive an event', (done) => {
    third.events.once('test', (event) => {
      expect(event.origin).toBe(second.events.id);
      done();
    });

    second.events.emit({
      type: 'test',
      data: 'foo',
    });
  });

  it('should emit and receive a second, large event', (done) => {
    third.events.once('test:2', (event) => {
      expect(event.origin).toBe(second.events.id);
      done();
    });

    second.events.emit({
      type: 'test:2',
      data: crypto.randomBytes(4096).toString('hex'),
    });
  });

  it('should emit and receive a third event', (done) => {
    third.events.once('test:3', (event) => {
      expect(event.origin).toBe(second.events.id);
      done();
    });

    second.events.emit({
      type: 'test:3',
      data: 'third',
    });
  });

  it('should emit and receive a fourth event', (done) => {
    third.events.once('test:4', (event) => {
      expect(event.origin).toBe(first.events.id);
      done();
    });

    first.events.emit({
      type: 'test:4',
      data: 'four',
    });
  });

  it('should stop the first mesh server', (done) => {
    first.mesh.stop(done);
  });

  it('should stop the second mesh server', (done) => {
    second.mesh.stop(done);
  });

  it('should stop the third mesh server', (done) => {
    third.mesh.stop(done);
  });
});
