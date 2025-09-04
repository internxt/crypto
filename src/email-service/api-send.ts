import emailjs from '@emailjs/browser';
import envService from '../utils/env';
import { EmailPublicParameters } from '../types';

/**
 * Sends an email to the server
 *
 * @param content - The email content (encrypted)
 * @param param - The email public parameters
 * @returns The server response
 */
export async function sendEmail(content: string, param: EmailPublicParameters) {
  try {
    const templateParams = {
      from_email: param.sender.email,
      from_name: param.sender.name,
      to_email: param.recipient.email,
      to_name: param.recipient.name,
      email_subject: param.subject,
      email_body: content,
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
