'use strict';

const { v4: uuid } = require('uuid');
const CircularSeen = require('./circularSeen');

const CAPACITY = 10;

describe('Skyfall Mesh Networking Circular Seen Test', () => {
  let seen;
  const initial = uuid();

  it(`shoud create a new circular seen object with capacity ${ CAPACITY }`, () => {
    seen = new CircularSeen(CAPACITY);
  });

  it('should add and verify the presence of one id', () => {
    seen.add(initial);
    expect(seen.has(initial)).toBe(true);
  });

  it(`should add ${ CAPACITY } ids and verify the initial id is not present`, () => {
    for (let i = 0; i < CAPACITY; i++) {
      seen.add(uuid());
    }

    expect(seen.has(initial)).toBe(false);
  });
});
