import { Email } from '../utils/types';
import { Buffer } from 'buffer';

export function emailToBinary(email: Email): Uint8Array {
  try {
    const json = JSON.stringify(email);
    const buffer = Buffer.from(json);
    return new Uint8Array(buffer);
  } catch (error) {
    throw new Error(`Cannot convert email to Uint8Array: ${error}`);
  }
}

export function binaryToEmail(array: Uint8Array): Email {
  try {
    const json = Buffer.from(array).toString('utf-8');
    const email: Email = JSON.parse(json);
    return email;
  } catch (error) {
    throw new Error(`Cannot convert Uint8Array to email: ${error}`);
  }
}
