import emailjs, { EmailJSResponseStatus } from '@emailjs/browser';
import envService from '../utils/env';
import { User } from '../utils/types';

export async function sendEncryptedEmail(
  subject: string,
  encryptedText: string,
  encryptedKey: string,
  sender: User,
  recipient: User,
): Promise<void> {
  try {
    const templateParams = {
      from_email: sender.email,
      from_name: sender.name,
      to_email: recipient.email,
      to_name: recipient.name,
      encrypted_subject: subject,
      encrypted_body: encryptedText,
      encrypted_symmetric_key: encryptedKey,
      timestamp: new Date().toISOString(),
    };

    const serviceId = envService.getVariable('serviceID');
    const templateId = envService.getVariable('templateID');
    const publicKey = envService.getVariable('publicKey');

    const response = await emailjs.send(serviceId, templateId, templateParams, publicKey);

    console.log('Encrypted email sent successfully:', response);
    return;
  } catch (error) {
    if (error instanceof EmailJSResponseStatus) {
      console.log('EMAILJS FAILED...', error);
      return;
    }

    console.log('ERROR', error);
  }
}
