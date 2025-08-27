import emailjs from '@emailjs/browser';
import envService from '../utils/env';
import { User } from '../types';

/**
 * Sends an email to the server
 *
 * @param subject - The email subject
 * @param body - The email body
 * @param sender - The email sender
 * @param recipient - The email recipient
 * @returns The server response
 */
export async function sendEmail(subject: string, body: string, sender: User, recipient: User) {
  try {
    const templateParams = {
      from_email: sender.email,
      from_name: sender.name,
      to_email: recipient.email,
      to_name: recipient.name,
      email_subject: subject,
      email_body: body,
      timestamp: new Date().toISOString(),
    };

    const serviceId = envService.getVariable('serviceID');
    const templateId = envService.getVariable('templateID');
    const publicKey = envService.getVariable('publicKey');

    await emailjs.send(serviceId, templateId, templateParams, publicKey).then(
      (response) => {
        console.log('SUCCESS!', response.status, response.text);
      },
      (err) => {
        throw new Error(`emailjs error: ${err}`);
      },
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to send an email: ${errorMessage}`);
  }
}
